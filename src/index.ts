import cryptolib from "crypto";
import { Client } from "ldapts";

const useMasterKey = true;

const PARSE_LDAP_FUNCTION_NAME = process.env.PARSE_LDAP_FUNCTION_NAME || "ldap_login";

const PARSE_LDAP_URL = process.env.PARSE_LDAP_URL || "ldap://127.0.0.1:389";
const PARSE_LDAP_BASEPATH = process.env.PARSE_LDAP_BASEPATH || "";
const PARSE_LDAP_LOGIN_BIND_DN = process.env.PARSE_LDAP_LOGIN_BIND_DN || "";
const PARSE_LDAP_LOGIN_BIND_MAP_FILTER = process.env.PARSE_LDAP_LOGIN_BIND_MAP_FILTER;
const PARSE_LDAP_LOGIN_BIND_MAP_SCOPE: "base" | "children" | "one" | "sub" | undefined =
  (process.env.PARSE_LDAP_LOGIN_BIND_MAP_SCOPE as "base" | "children" | "one" | "sub" | undefined) || "sub";
const PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE = process.env.PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE || "dn";
const PARSE_LDAP_LOGIN_BIND_MAP_TO = process.env.PARSE_LDAP_LOGIN_BIND_MAP_TO || "%output%";
const PARSE_LDAP_LOGIN_SEARCH_DN = process.env.PARSE_LDAP_LOGIN_SEARCH_DN;
const PARSE_LDAP_LOGIN_SEARCH_FILTER = process.env.PARSE_LDAP_LOGIN_SEARCH_FILTER;
const PARSE_LDAP_LOGIN_SEARCH_SCOPE: "sub" | "base" | "children" | "one" | undefined =
  (process.env.PARSE_LDAP_LOGIN_SEARCH_SCOPE as "sub" | "base" | "children" | "one" | undefined) || "sub";

const PARSE_LDAP_DN_ATTRIBUTE = process.env.PARSE_LDAP_DN_ATTRIBUTE || "dn";
const PARSE_LDAP_USERNAME_ATTRIBUTE = process.env.PARSE_LDAP_USERNAME_ATTRIBUTE || "uid";
const PARSE_LDAP_EMAIL_ATTRIBUTE = process.env.PARSE_LDAP_EMAIL_ATTRIBUTE || "mail";
const PARSE_LDAP_NAME_ATTRIBUTE = process.env.PARSE_LDAP_NAME_ATTRIBUTE || "cn";

const PARSE_LDAP_PARSE_LDAP_ATTRIBUTE = process.env.PARSE_LDAP_PARSE_LDAP_ATTRIBUTE || "ldap";
const PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE = process.env.PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE || "ldap_dn";

const PARSE_LDAP_SERVICE_USER_DN = process.env.PARSE_LDAP_SERVICE_USER_DN || "";
const PARSE_LDAP_SERVICE_USER_PW = process.env.PARSE_LDAP_SERVICE_USER_PW || "";
const PARSE_LDAP_SERVICE_GROUP_DN = process.env.PARSE_LDAP_SERVICE_GROUP_DN || "";
const PARSE_LDAP_SERVICE_INTERVAL = parseInt(process.env.PARSE_LDAP_SERVICE_INTERVAL || "");
let PARSE_LDAP_EXPIRE_LENGTH = process.env.PARSE_LDAP_EXPIRE_LENGTH
  ? new Date(Date.now() + Number(process.env.PARSE_LDAP_EXPIRE_LENGTH) * 1000)
  : new Date(Date.now() + 1000 * 60 * 60 * 24 * 365);

const PARSE_LDAP_UNIFY_CREDENTIALS = process.env.PARSE_LDAP_UNIFY_CREDENTIALS === "true";
const PARSE_LDAP_DEFAULT_TENANT_ID = process.env.PARSE_LDAP_DEFAULT_TENANT_ID || undefined;
const PARSE_LDAP_REJECT_UNAUTHORIZED = process.env.PARSE_LDAP_REJECT_UNAUTHORIZED === "true";

const clientOptions = PARSE_LDAP_REJECT_UNAUTHORIZED ? {url: PARSE_LDAP_URL} : {url: PARSE_LDAP_URL, tlsOptions: {rejectUnauthorized: false}};

export async function init() {
  if (!PARSE_LDAP_URL) {
    console.log("Parse LDAP Plugin is not active. PARSE_LDAP_URL is required.");
    return;
  }

  if (!PARSE_LDAP_LOGIN_BIND_DN) {
    console.log("Parse LDAP Plugin is not active. PARSE_LDAP_LOGIN_BIND_DN is required.");
    return;
  }

  if (PARSE_LDAP_LOGIN_BIND_MAP_FILTER && (!PARSE_LDAP_SERVICE_USER_DN || !PARSE_LDAP_SERVICE_USER_PW)) {
    console.log(
      "Parse LDAP Plugin is not active. PARSE_LDAP_LOGIN_BIND_MAP_FILTER requires PARSE_LDAP_SERVICE_USER_DN and PARSE_LDAP_SERVICE_USER_PW to be set."
    );
    return;
  }

  if (PARSE_LDAP_SERVICE_GROUP_DN && (!PARSE_LDAP_SERVICE_USER_DN || !PARSE_LDAP_SERVICE_USER_PW)) {
    console.log(
      "Parse LDAP Plugin is not active. PARSE_LDAP_SERVICE_GROUP_DN requires PARSE_LDAP_SERVICE_USER_DN and PARSE_LDAP_SERVICE_USER_PW to be set."
    );
    return;
  }

  console.log("Parse LDAP Plugin is active.");

  if (
    Number.isInteger(PARSE_LDAP_SERVICE_INTERVAL) &&
    PARSE_LDAP_SERVICE_USER_DN &&
    PARSE_LDAP_SERVICE_USER_PW &&
    PARSE_LDAP_SERVICE_GROUP_DN
  ) {
    console.log("Parse LDAP Plugin periodic Group Check is active.");

    setInterval(validateParseUsers, PARSE_LDAP_SERVICE_INTERVAL * 1000);

    async function validateParseUsers() {
      try {
        // Lookup LDAP users in Parse
        const query = new Parse.Query(Parse.User).equalTo(PARSE_LDAP_PARSE_LDAP_ATTRIBUTE, true);
        const users = await query.find({ useMasterKey });

        // Fetch valid LDAP users
        const members = await getValidGroupMembers();

        // Check every Parse User
        for (const user of users) {
          const dn = user.get(PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE);

          if (!members.includes(dn)) {
            // Overwrite the password, if the user is not a valid LDAP user
            // This will also delete all sessions of the user

            // Create a random password:
            const token = cryptolib.randomBytes(64).toString("hex");

            // Set the password and save the user
            user.set("password", token);
            await user.save(null, { useMasterKey });
          }
        }
      } catch (error) {
        console.warn("Error in the PARSE_LDAP_SERVICE_INTERVAL:", error);
      }
    }
  }

  Parse.Cloud.define(PARSE_LDAP_FUNCTION_NAME, async function (request) {
    try {
      // Get credentials from request
      const { username, password } = request.params;

      // Validate credentials
      const user = await validateCredentials(username, password);

      if (PARSE_LDAP_SERVICE_USER_DN && PARSE_LDAP_SERVICE_USER_PW && PARSE_LDAP_SERVICE_GROUP_DN) {
        const isAuthorized = await validateGroupMember(user.dn ? user.dn : user.username ? user.username : "");

        if (!isAuthorized) {
          throw new Parse.Error(101, "Invalid username/password.");
        }
      }

      // Create a random password:
      const token = cryptolib.randomBytes(64).toString("hex");

      // Lookup user in Parse
      const query = new Parse.Query(Parse.User).equalTo("username", user.username);

      const user_a = await query.first({ useMasterKey });

      // If there is a match
      if (user_a) {
        user_a.set("username", user.username);
        user_a.set("email", user.email);
        user_a.set("name", user.name);
        user_a.set(PARSE_LDAP_PARSE_LDAP_ATTRIBUTE, true);
        user_a.set(PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE, user.dn);

        await user_a.save(null, { useMasterKey });

        const sessionToken = "r:" + token.slice(0, 32);
        PARSE_LDAP_EXPIRE_LENGTH = process.env.PARSE_LDAP_EXPIRE_LENGTH
          ? new Date(Date.now() + Number(process.env.PARSE_LDAP_EXPIRE_LENGTH) * 1000)
          : new Date(Date.now() + 1000 * 60 * 60 * 24 * 365);
        const session = new Parse.Object("_Session", {
          sessionToken,
          user: user_a,
          restricted: false,
          expiresAt: PARSE_LDAP_EXPIRE_LENGTH,
          installationId: request.installationId,
          createdWith: {
            action: "login",
            provider: "openinc-ldap",
          },
        });

        await session.save(null, { useMasterKey });

        return { ...user, session: sessionToken };
      }

      // If lookup failed: Create missing user in Parse
      const user_c = new Parse.User();

      user_c.set("username", user.username);
      user_c.set("email", user.email);
      user_c.set("name", user.name);
      user_c.set(PARSE_LDAP_PARSE_LDAP_ATTRIBUTE, true);
      user_c.set(PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE, user.dn);
      user_c.set("password", token);

      if (PARSE_LDAP_DEFAULT_TENANT_ID !== undefined) {
        const tenant = new Parse.Object("OD3_Tenant");
        tenant.id = PARSE_LDAP_DEFAULT_TENANT_ID;
        user_c.set("tenant", tenant);
      }

      await user_c.signUp();

      const user_b = await Parse.User.logIn(user.username as string, token);

      return { ...user, session: user_b.getSessionToken() };
    } catch (error) {
      console.error(error);

      throw new Parse.Error(101, "Invalid username/password.");
    }
  });
}

async function validateCredentials(username: string, password: string) {
  const client = new Client(clientOptions);

  try {
    const user = username;
    const userWithoutDomain = username.split("\\").pop() as string;
    const basepath = PARSE_LDAP_BASEPATH;

    const bindPath = await getBindPath({ user, userWithoutDomain, basepath });

    await client.bind(bindPath, password);

    const searchPath = PARSE_LDAP_LOGIN_SEARCH_DN
      ? replaceParams(PARSE_LDAP_LOGIN_SEARCH_DN, { user, userWithoutDomain, basepath })
      : bindPath;

    const searchFilter = PARSE_LDAP_LOGIN_SEARCH_FILTER
      ? replaceParams(PARSE_LDAP_LOGIN_SEARCH_FILTER, { user, userWithoutDomain, basepath })
      : undefined;

    const { searchEntries } = await client.search(searchPath, {
      scope: PARSE_LDAP_LOGIN_SEARCH_SCOPE,
      filter: searchFilter,
      attributes: [
        PARSE_LDAP_DN_ATTRIBUTE,
        PARSE_LDAP_USERNAME_ATTRIBUTE,
        PARSE_LDAP_EMAIL_ATTRIBUTE,
        PARSE_LDAP_NAME_ATTRIBUTE,
      ],
    });

    //Filter out entries without dn
    let searchResult = searchEntries.filter((entry: any) => {
      // Check if entry[PARSE_LDAP_DN_ATTRIBUTE] is an array.
      // If so, check if the array is not empty.

      if (Array.isArray(entry[PARSE_LDAP_DN_ATTRIBUTE]) && entry[PARSE_LDAP_DN_ATTRIBUTE].length > 0) {
        return true;
      }

      // Check if entry[PARSE_LDAP_DN_ATTRIBUTE] is a string.
      // If so, check if the string is not empty.

      if (typeof entry[PARSE_LDAP_DN_ATTRIBUTE] === "string" && entry[PARSE_LDAP_DN_ATTRIBUTE].length > 0) {
        return true;
      }

      return false;
    });

    // Log if searchResult is not 1
    if (searchResult.length !== 1) {
      console.log("Search entries is not 1.");
      searchResult.forEach((entry: any) => {
        console.log(entry[PARSE_LDAP_DN_ATTRIBUTE]);
      });

      // Throw error
      throw new Error(`Invalid Search Entries Length: ${searchResult.length}`);
    }

    const usedSearchResult = searchResult[0];

    if (usedSearchResult === undefined) {
      throw new Error("No search result found.");
    }

    return {
      dn: usedSearchResult[PARSE_LDAP_DN_ATTRIBUTE],
      email: PARSE_LDAP_UNIFY_CREDENTIALS
        ? usedSearchResult[PARSE_LDAP_EMAIL_ATTRIBUTE]
          ? getTypedAttribute(usedSearchResult[PARSE_LDAP_EMAIL_ATTRIBUTE]).toLowerCase().trim()
          : ""
        : usedSearchResult[PARSE_LDAP_EMAIL_ATTRIBUTE],
      username: PARSE_LDAP_UNIFY_CREDENTIALS
        ? usedSearchResult[PARSE_LDAP_USERNAME_ATTRIBUTE]
          ? getTypedAttribute(usedSearchResult[PARSE_LDAP_USERNAME_ATTRIBUTE]).toLowerCase().trim()
          : ""
        : usedSearchResult[PARSE_LDAP_USERNAME_ATTRIBUTE],
      name: usedSearchResult[PARSE_LDAP_NAME_ATTRIBUTE],
    };
  } catch (error) {
    throw error;
  } finally {
    await client.unbind();
  }
}

async function getBindPath(params: Record<string, string>) {
  if (!PARSE_LDAP_LOGIN_BIND_MAP_FILTER) {
    return replaceParams(PARSE_LDAP_LOGIN_BIND_DN, params);
  }

  const client = new Client(clientOptions);

  try {
    await client.bind(
      replaceParams(PARSE_LDAP_SERVICE_USER_DN, { basepath: PARSE_LDAP_BASEPATH }),
      PARSE_LDAP_SERVICE_USER_PW
    );

    const { searchEntries } = await client.search(replaceParams(PARSE_LDAP_LOGIN_BIND_DN, params), {
      filter: replaceParams(PARSE_LDAP_LOGIN_BIND_MAP_FILTER, params),
      scope: PARSE_LDAP_LOGIN_BIND_MAP_SCOPE,
    });

    const [user] = searchEntries;

    if (!user) {
      throw new Error(`User Not Found While Mapping: ${searchEntries.length}`);
    }

    const attribute = user[PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE];

    if (!attribute) {
      throw new Error(`Attribute '${PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE}' Not Found in User: ${user}`);
    }

    return replaceParams(PARSE_LDAP_LOGIN_BIND_MAP_TO, { ...params, output: getTypedAttribute(attribute) });
  } catch (error) {
    throw error;
  } finally {
    await client.unbind();
  }
}

async function validateGroupMember(dn: string | string[] | Buffer | Buffer[]): Promise<boolean> {
  const client = new Client(clientOptions);

  try {
    await client.bind(
      replaceParams(PARSE_LDAP_SERVICE_USER_DN, { basepath: PARSE_LDAP_BASEPATH }),
      PARSE_LDAP_SERVICE_USER_PW
    );

    const { searchEntries } = await client.search(
      replaceParams(PARSE_LDAP_SERVICE_GROUP_DN, { basepath: PARSE_LDAP_BASEPATH }),
      {
        scope: "base",
      }
    );

    const [group] = searchEntries;

    if (!group) {
      throw new Error(`Invalid Search Entries Length: ${searchEntries.length}`);
    }

    if (!group.member) {
      throw new Error(`Group '${PARSE_LDAP_SERVICE_GROUP_DN}' has no member`);
    }

    if (Array.isArray(group.member) && !Array.isArray(dn)) {
      // @ts-ignore
      return group.member.includes(dn.toString());
    } else {
      return group.member === dn;
    }
  } catch (error) {
    throw error;
  } finally {
    await client.unbind();
  }
}

async function getValidGroupMembers() {
  const client = new Client(clientOptions);

  try {
    await client.bind(
      replaceParams(PARSE_LDAP_SERVICE_USER_DN, { basepath: PARSE_LDAP_BASEPATH }),
      PARSE_LDAP_SERVICE_USER_PW
    );

    const { searchEntries } = await client.search(
      replaceParams(PARSE_LDAP_SERVICE_GROUP_DN, { basepath: PARSE_LDAP_BASEPATH }),
      {
        scope: "base",
      }
    );

    const [group] = searchEntries;

    if (!group) {
      throw new Error(`Invalid Search Entries Length: ${searchEntries.length}`);
    }

    if (Array.isArray(group.member)) {
      return group.member;
    } else {
      return [group.member];
    }
  } catch (error) {
    throw error;
  } finally {
    await client.unbind();
  }
}

function getTypedAttribute(attribute: string | string[] | Buffer | Buffer[]): string {
  let typedAttribute = "";

  if (typeof attribute === "undefined") {
    return typedAttribute;
  }

  if (attribute instanceof Array && attribute.length > 0) {
    if (attribute instanceof Buffer) {
      typedAttribute = attribute[0] ? attribute[0].toString() : "";
    }

    if (typeof attribute === "string") {
      typedAttribute = attribute[0];
    }
  }

  if (attribute instanceof Buffer) {
    typedAttribute = attribute.toString();
  }

  if (typeof attribute === "string") {
    typedAttribute = attribute;
  }
  return typedAttribute;
}

function replaceParams(input: string, params: Record<string, string>): string {
  let inputWithParams = input;

  for (const [param, value] of Object.entries(params)) {
    inputWithParams = inputWithParams.replace(`%${param}%`, value);
  }

  return inputWithParams;
}
