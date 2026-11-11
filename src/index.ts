import cryptolib, { X509Certificate } from "crypto";
import fs from "fs";
import { Client, type ClientOptions } from "ldapts";
import type { ConnectionOptions } from "tls";
import type ParseNode from "parse/node";

type ParseInstance = typeof ParseNode;

// Must be the host's Parse instance (the one Parse Server extends with Parse.Cloud).
// Importing "parse/node" here could resolve to a different copy and register
// cloud functions on an instance Parse Server never sees.
let Parse!: ParseInstance;

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
const PARSE_LDAP_REJECT_UNAUTHORIZED = process.env.PARSE_LDAP_REJECT_UNAUTHORIZED !== "false";
const PARSE_LDAP_CA_FILE = process.env.PARSE_LDAP_CA_FILE || "";
// Timeout in seconds for connecting and for each LDAP operation. ldapts has no timeout by default,
// so an unreachable server would let the login request hang forever without any log output.
const PARSE_LDAP_TIMEOUT = Number(process.env.PARSE_LDAP_TIMEOUT || "10");

let clientOptions: ClientOptions = { url: PARSE_LDAP_URL };

function createClientOptions(): ClientOptions {
  const timeout = Number.isFinite(PARSE_LDAP_TIMEOUT) && PARSE_LDAP_TIMEOUT > 0 ? PARSE_LDAP_TIMEOUT * 1000 : 10000;
  const baseOptions: ClientOptions = { url: PARSE_LDAP_URL, timeout, connectTimeout: timeout };

  // ldapts switches to TLS whenever tlsOptions are set, even for ldap:// URLs.
  // Only pass tlsOptions for ldaps://, otherwise plain LDAP connections would hang.
  if (!PARSE_LDAP_URL.toLowerCase().startsWith("ldaps://")) {
    return baseOptions;
  }

  const tlsOptions: ConnectionOptions = { rejectUnauthorized: PARSE_LDAP_REJECT_UNAUTHORIZED };

  if (PARSE_LDAP_CA_FILE) {
    tlsOptions.ca = readCaFile(PARSE_LDAP_CA_FILE);
  }

  if (!PARSE_LDAP_REJECT_UNAUTHORIZED) {
    console.warn(
      "Parse LDAP Plugin: TLS certificate validation is disabled (PARSE_LDAP_REJECT_UNAUTHORIZED=false). Do not use this in production."
    );
  }

  return { ...baseOptions, tlsOptions };
}

const LOG_PREFIX = "[parse-server-ldap]";

const TLS_ERROR_HINTS: Record<string, string> = {
  UNABLE_TO_GET_ISSUER_CERT: "The CA certificate is not trusted. Check PARSE_LDAP_CA_FILE.",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "The CA certificate is not trusted. Check PARSE_LDAP_CA_FILE.",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "The CA certificate is not trusted. Check PARSE_LDAP_CA_FILE.",
  SELF_SIGNED_CERT_IN_CHAIN: "The CA certificate is not trusted. Check PARSE_LDAP_CA_FILE.",
  DEPTH_ZERO_SELF_SIGNED_CERT: "The server uses a self-signed certificate. Add it to PARSE_LDAP_CA_FILE.",
  CERT_HAS_EXPIRED: "The server certificate has expired.",
  ERR_TLS_CERT_ALTNAME_INVALID:
    "The host name in PARSE_LDAP_URL does not match the server certificate. Use the DNS name from the certificate.",
  ECONNREFUSED: "The LDAP server refused the connection. Check host and port in PARSE_LDAP_URL.",
  ENOTFOUND: "The host in PARSE_LDAP_URL could not be resolved.",
  ETIMEDOUT: "Connection to the LDAP server timed out.",
  TimeoutError: "The LDAP server did not answer in time (PARSE_LDAP_TIMEOUT). Check host, port and protocol (ldap:// vs. ldaps://) in PARSE_LDAP_URL and firewall rules.",
  ECONNRESET:
    "The connection was reset. Check if PARSE_LDAP_URL uses the right protocol (ldap:// vs. ldaps://) for the port.",
};

/**
 * Adds context (which step failed) to an error and a hint for common connection/TLS problems.
 * The original error is not attached as `cause` on purpose: TLS errors contain the whole
 * peer certificate, which would flood the logs on every failed login.
 */
async function withContext<T>(context: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    const err = error as Error & { code?: string };
    const name = err?.name && err.name !== "Error" ? err.name : undefined;
    const details = [name, err?.code, err?.message].filter(Boolean).join(": ") || String(error);
    const hint =
      (err?.code ? TLS_ERROR_HINTS[err.code] : undefined) ??
      (err?.name === "TimeoutError" || /timeout/i.test(err?.message ?? "") ? TLS_ERROR_HINTS.TimeoutError : undefined);
    const wrapped = new Error(`${context}: ${details}${hint ? ` -> ${hint}` : ""}`);
    if (err?.code) Object.assign(wrapped, { code: err.code });
    throw wrapped;
  }
}

function readCaFile(path: string): string {
  const content = fs.readFileSync(path);

  // PEM file (may contain multiple certificates, e.g. root + intermediate)
  if (content.toString("utf8").includes("-----BEGIN CERTIFICATE-----")) {
    return content.toString("utf8");
  }

  // DER encoded certificate (default export format of Windows / AD CS ".cer" files)
  return new X509Certificate(content).toString();
}

export async function init(parse?: ParseInstance) {
  const instance = parse ?? (globalThis as { Parse?: ParseInstance }).Parse;

  if (!instance) {
    console.log("Parse LDAP Plugin is not active. No Parse instance passed to init() and no global Parse found.");
    return;
  }

  Parse = instance;

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

  try {
    clientOptions = createClientOptions();
  } catch (error) {
    console.log(`Parse LDAP Plugin is not active. Could not read PARSE_LDAP_CA_FILE '${PARSE_LDAP_CA_FILE}':`, error);
    return;
  }

  console.log(
    `Parse LDAP Plugin is active. URL: ${PARSE_LDAP_URL}, TLS: ${
      clientOptions.tlsOptions
        ? `ldaps (certificate validation: ${PARSE_LDAP_REJECT_UNAUTHORIZED ? "on" : "OFF"}, CA file: ${
            PARSE_LDAP_CA_FILE || "none, using Node.js default CAs"
          })`
        : "none (plain ldap://, credentials are sent unencrypted)"
    }, bind mapping: ${PARSE_LDAP_LOGIN_BIND_MAP_FILTER ? "on" : "off"}, group check: ${
      PARSE_LDAP_SERVICE_GROUP_DN || "off"
    }`
  );

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
        const members = (await getValidGroupMembers()).filter((member) => !!member);

        // Safety net: an empty group is most likely a misconfiguration or missing permissions
        // of the service user. Do not lock out every LDAP user in that case.
        if (members.length === 0) {
          console.error(
            `${LOG_PREFIX} Group check: group '${PARSE_LDAP_SERVICE_GROUP_DN}' returned no members. Skipping, no users are deactivated. Check the group and the permissions of PARSE_LDAP_SERVICE_USER_DN.`
          );
          return;
        }

        let deactivated = 0;

        // Check every Parse User
        for (const user of users) {
          const dn = user.get(PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE);

          if (!members.includes(dn)) {
            console.warn(
              `${LOG_PREFIX} Group check: user "${user.get("username")}" (${dn}) is not a member of '${PARSE_LDAP_SERVICE_GROUP_DN}' anymore. Password is reset and sessions are revoked.`
            );
            deactivated++;

            // Overwrite the password, if the user is not a valid LDAP user
            // This will also delete all sessions of the user

            // Create a random password:
            const token = cryptolib.randomBytes(64).toString("hex");

            // Set the password and save the user
            user.set("password", token);
            await user.save(null, { useMasterKey });
          }
        }

        if (deactivated > 0) {
          console.log(`${LOG_PREFIX} Group check: ${deactivated} of ${users.length} LDAP users deactivated.`);
        }
      } catch (error) {
        console.error(`${LOG_PREFIX} Group check (PARSE_LDAP_SERVICE_INTERVAL) failed:`, error);
      }
    }
  }

  Parse.Cloud.define(PARSE_LDAP_FUNCTION_NAME, async function (request) {
    // Get credentials from request
    const { username, password } = request.params;

    try {
      // An empty password would result in an unauthenticated bind (RFC 4513),
      // which many LDAP servers (i.e. Active Directory) accept as successful.
      if (typeof username !== "string" || !username || typeof password !== "string" || !password) {
        throw new Error("Username or password is empty.");
      }

      // Validate credentials
      const user = await validateCredentials(username, password);

      if (PARSE_LDAP_SERVICE_USER_DN && PARSE_LDAP_SERVICE_USER_PW && PARSE_LDAP_SERVICE_GROUP_DN) {
        const isAuthorized = await withContext("Group check", () =>
          validateGroupMember(user.dn ? user.dn : user.username ? user.username : "")
        );

        if (!isAuthorized) {
          throw new Error(`User ${user.dn} is not a member of '${PARSE_LDAP_SERVICE_GROUP_DN}'.`);
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

        console.log(`${LOG_PREFIX} User "${user.username}" logged in.`);

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

      console.log(`${LOG_PREFIX} User "${user.username}" created and logged in.`);

      return { ...user, session: user_b.getSessionToken() };
    } catch (error) {
      // Never log the password here
      console.error(`${LOG_PREFIX} Login failed for user "${username}":`, error);

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

    await withContext(`User bind as '${bindPath}' failed`, () => client.bind(bindPath, password));

    const searchPath = PARSE_LDAP_LOGIN_SEARCH_DN
      ? replaceParams(PARSE_LDAP_LOGIN_SEARCH_DN, { user, userWithoutDomain, basepath })
      : bindPath;

    const searchFilter = PARSE_LDAP_LOGIN_SEARCH_FILTER
      ? replaceParams(PARSE_LDAP_LOGIN_SEARCH_FILTER, { user, userWithoutDomain, basepath })
      : undefined;

    const { searchEntries } = await withContext(
      `User profile search in '${searchPath}' (filter: ${searchFilter ?? "none"}) failed`,
      () =>
        client.search(searchPath, {
          scope: PARSE_LDAP_LOGIN_SEARCH_SCOPE,
          filter: searchFilter,
          attributes: [
            PARSE_LDAP_DN_ATTRIBUTE,
            PARSE_LDAP_USERNAME_ATTRIBUTE,
            PARSE_LDAP_EMAIL_ATTRIBUTE,
            PARSE_LDAP_NAME_ATTRIBUTE,
          ],
        })
    );

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
      throw new Error(
        `User profile search in '${searchPath}' (filter: ${searchFilter ?? "none"}, scope: ${PARSE_LDAP_LOGIN_SEARCH_SCOPE}) returned ${searchResult.length} entries with attribute '${PARSE_LDAP_DN_ATTRIBUTE}', expected exactly 1.` +
          (searchResult.length > 0
            ? ` Found: ${searchResult.map((entry: any) => entry[PARSE_LDAP_DN_ATTRIBUTE]).join("; ")}`
            : "")
      );
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

  const searchPath = replaceParams(PARSE_LDAP_LOGIN_BIND_DN, params);
  const filter = replaceParams(PARSE_LDAP_LOGIN_BIND_MAP_FILTER, params);

  try {
    await bindServiceUser(client);

    const { searchEntries } = await withContext(
      `Bind mapping search in '${searchPath}' (filter: ${filter}) failed`,
      () => client.search(searchPath, { filter, scope: PARSE_LDAP_LOGIN_BIND_MAP_SCOPE })
    );

    const [user] = searchEntries;

    if (!user) {
      throw new Error(`Bind mapping: no user found in '${searchPath}' with filter ${filter}.`);
    }

    if (searchEntries.length > 1) {
      console.warn(
        `${LOG_PREFIX} Bind mapping: ${searchEntries.length} entries found in '${searchPath}' with filter ${filter}, using the first one: ${user.dn}`
      );
    }

    const attribute = user[PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE];

    if (!attribute) {
      throw new Error(
        `Bind mapping: attribute '${PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE}' (PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE) not found in ${user.dn}.`
      );
    }

    return replaceParams(PARSE_LDAP_LOGIN_BIND_MAP_TO, { ...params, output: getTypedAttribute(attribute) });
  } catch (error) {
    throw error;
  } finally {
    await client.unbind();
  }
}

async function bindServiceUser(client: Client) {
  const serviceDn = replaceParams(PARSE_LDAP_SERVICE_USER_DN, { basepath: PARSE_LDAP_BASEPATH });

  await withContext(`Service user bind as '${serviceDn}' (PARSE_LDAP_SERVICE_USER_DN) failed`, () =>
    client.bind(serviceDn, PARSE_LDAP_SERVICE_USER_PW)
  );
}

async function searchGroup(client: Client) {
  const groupDn = replaceParams(PARSE_LDAP_SERVICE_GROUP_DN, { basepath: PARSE_LDAP_BASEPATH });

  const { searchEntries } = await withContext(`Reading group '${groupDn}' (PARSE_LDAP_SERVICE_GROUP_DN) failed`, () =>
    client.search(groupDn, { scope: "base" })
  );

  const [group] = searchEntries;

  if (!group) {
    throw new Error(`Group '${groupDn}' (PARSE_LDAP_SERVICE_GROUP_DN) not found.`);
  }

  return group;
}

async function validateGroupMember(dn: string | string[] | Buffer | Buffer[]): Promise<boolean> {
  const client = new Client(clientOptions);

  try {
    await bindServiceUser(client);

    const group = await searchGroup(client);

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
    await bindServiceUser(client);

    const group = await searchGroup(client);

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
