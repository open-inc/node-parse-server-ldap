const crypto = require("crypto");
const { Client } = require("ldapts");

const useMasterKey = true;

module.exports = init;

const PARSE_LDAP_ACTIVE = (process.env.PARSE_LDAP_ACTIVE ?? true) == "true";
const PARSE_LDAP_FUNCTION_NAME = process.env.PARSE_LDAP_FUNCTION_NAME || "ldap_login";

const PARSE_LDAP_URL = process.env.PARSE_LDAP_URL || "ldap://127.0.0.1:389";
const PARSE_LDAP_BASEPATH = process.env.PARSE_LDAP_BASEPATH;
const PARSE_LDAP_LOGIN_BIND_DN = process.env.PARSE_LDAP_LOGIN_BIND_DN;
const PARSE_LDAP_LOGIN_SEARCH_DN = process.env.PARSE_LDAP_LOGIN_SEARCH_DN;
const PARSE_LDAP_LOGIN_SEARCH_FILTER = process.env.PARSE_LDAP_LOGIN_SEARCH_FILTER;
const PARSE_LDAP_LOGIN_STRIP_AD_DOMAIN = process.env.PARSE_LDAP_LOGIN_STRIP_AD_DOMAIN == "true";

const PARSE_LDAP_DN_ATTRIBUTE = process.env.PARSE_LDAP_DN_ATTRIBUTE || "dn";
const PARSE_LDAP_USERNAME_ATTRIBUTE = process.env.PARSE_LDAP_USERNAME_ATTRIBUTE || "uid";
const PARSE_LDAP_EMAIL_ATTRIBUTE = process.env.PARSE_LDAP_EMAIL_ATTRIBUTE || "mail";
const PARSE_LDAP_NAME_ATTRIBUTE = process.env.PARSE_LDAP_NAME_ATTRIBUTE || "cn";

const PARSE_LDAP_PARSE_LDAP_ATTRIBUTE = process.env.PARSE_LDAP_PARSE_LDAP_ATTRIBUTE || "ldap";
const PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE = process.env.PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE || "ldap_dn";

const PARSE_LDAP_SERVICE_USER_DN = process.env.PARSE_LDAP_SERVICE_USER_DN;
const PARSE_LDAP_SERVICE_USER_PW = process.env.PARSE_LDAP_SERVICE_USER_PW;
const PARSE_LDAP_SERVICE_GROUP_DN = process.env.PARSE_LDAP_SERVICE_GROUP_DN;
const PARSE_LDAP_SERVICE_INTERVAL = parseInt(process.env.PARSE_LDAP_SERVICE_INTERVAL);

async function init(Parse) {
  if (!PARSE_LDAP_ACTIVE || !PARSE_LDAP_URL || !PARSE_LDAP_BASEPATH || !PARSE_LDAP_LOGIN_BIND_DN) {
    console.log("Parse LDAP Plugin is not active.");
    return;
  }

  console.log("Parse LDAP Plugin is active.");

  if (
    Number.isInteger(PARSE_LDAP_SERVICE_INTERVAL) &&
    PARSE_LDAP_SERVICE_USER_DN &&
    PARSE_LDAP_SERVICE_USER_PW &&
    PARSE_LDAP_SERVICE_GROUP_DN
  ) {
    setInterval(validateParseUsers, PARSE_LDAP_SERVICE_INTERVAL);

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
            const token = crypto.randomBytes(64).toString("hex");

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

  Parse.Cloud.define(PARSE_LDAP_FUNCTION_NAME, async function(request) {
    try {
      // Get credentials from request
      const { username, password } = request.params;

      // Validate credentials
      const user = await validateCredentials(username, password);

      if (PARSE_LDAP_SERVICE_USER_DN && PARSE_LDAP_SERVICE_USER_PW && PARSE_LDAP_SERVICE_GROUP_DN) {
        const isAuthorized = await validateGroupMember(user.dn);

        if (!isAuthorized) {
          throw new Parse.Error(101, "Invalid username/password.");
        }
      }

      // Create a random password:
      const token = crypto.randomBytes(64).toString("hex");

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
        user_a.set("password", token);

        await user_a.save(null, { useMasterKey });

        const user_b = await Parse.User.logIn(user.username, token);

        return { ...user, session: user_b.getSessionToken() };
      }

      // If lookup failed: Create missing user in Parse
      const user_c = new Parse.User();

      user_c.set("username", user.username);
      user_c.set("email", user.email);
      user_c.set("name", user.name);
      user_c.set(PARSE_LDAP_PARSE_LDAP_ATTRIBUTE, true);
      user_a.set(PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE, user.dn);
      user_c.set("password", token);

      await user_c.signUp();

      return { ...user, session: user_c.getSessionToken() };
    } catch (error) {
      console.error(error);

      throw new Parse.Error(101, "Invalid username/password.");
    }
  });
}

async function validateCredentials(username, password) {
  const client = new Client({ url: PARSE_LDAP_URL });

  try {
    if (PARSE_LDAP_LOGIN_STRIP_AD_DOMAIN) {
      username = username.split("\\").pop();
    }

    const bindPath = PARSE_LDAP_LOGIN_BIND_DN.replace("%user%", username).replace("%basepath%", PARSE_LDAP_BASEPATH);

    await client.bind(bindPath, password);

    const searchPath = PARSE_LDAP_LOGIN_SEARCH_DN
      ? PARSE_LDAP_LOGIN_SEARCH_DN.replace("%user%", username).replace("%basepath%", PARSE_LDAP_BASEPATH)
      : bindPath;

    const searchFilter = PARSE_LDAP_LOGIN_SEARCH_FILTER
      ? PARSE_LDAP_LOGIN_SEARCH_FILTER.replace("%user%", username)
      : undefined;

    const { searchEntries } = await client.search(searchPath, {
      scope: "sub",
      filter: searchFilter,
      attributes: [
        PARSE_LDAP_DN_ATTRIBUTE,
        PARSE_LDAP_USERNAME_ATTRIBUTE,
        PARSE_LDAP_EMAIL_ATTRIBUTE,
        PARSE_LDAP_NAME_ATTRIBUTE
      ]
    });

    if (searchEntries.length !== 1) {
      throw new Error(`Invalid Search Entries Length: ${searchEntries.length}`);
    }

    return {
      dn: searchEntries[0][PARSE_LDAP_DN_ATTRIBUTE],
      email: searchEntries[0][PARSE_LDAP_EMAIL_ATTRIBUTE],
      username: searchEntries[0][PARSE_LDAP_USERNAME_ATTRIBUTE],
      name: searchEntries[0][PARSE_LDAP_NAME_ATTRIBUTE]
    };
  } catch (error) {
    throw error;
  } finally {
    await client.unbind();
  }
}

async function validateGroupMember(dn) {
  const client = new Client({ url: PARSE_LDAP_URL });

  try {
    await client.bind(
      PARSE_LDAP_SERVICE_USER_DN.replace("%basepath%", PARSE_LDAP_BASEPATH),
      PARSE_LDAP_SERVICE_USER_PW
    );

    const { searchEntries } = await client.search(
      PARSE_LDAP_SERVICE_GROUP_DN.replace("%basepath%", PARSE_LDAP_BASEPATH),
      {
        scope: "base"
      }
    );

    const [group] = searchEntries;

    if (!group) {
      throw new Error(`Invalid Search Entries Length: ${searchEntries.length}`);
    }

    if (!group.member) {
      throw new Error(`Group '${PARSE_LDAP_SERVICE_GROUP_DN}' has no member`);
    }

    if (Array.isArray(group.member)) {
      return group.member.includes(dn);
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
  const client = new Client({ url: PARSE_LDAP_URL });

  try {
    await client.bind(
      PARSE_LDAP_SERVICE_USER_DN.replace("%basepath%", PARSE_LDAP_BASEPATH),
      PARSE_LDAP_SERVICE_USER_PW
    );

    const { searchEntries } = await client.search(
      PARSE_LDAP_SERVICE_GROUP_DN.replace("%basepath%", PARSE_LDAP_BASEPATH),
      {
        scope: "base"
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

// async function test() {
//   try {
//     const user = await validateCredentials("user", "password");
//     const isAuthorized = await validateGroupMember(user.dn);

//     console.log(user, isAuthorized);

//     // const members = await getValidGroupMembers();
//     // console.log(members);
//   } catch (error) {
//     console.error(error);
//   }
// }

// test();
