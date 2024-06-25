# @openinc/parse-server-ldap

## Installation

```
npm i @openinc/parse-server-ldap
```

## Usage

Init LDAP plugin in a js file that will be loaded by Cloud Code.
Example:

```js
const init = async () => {
  console.log("Init LDAP Plugin.");
  const initLDAP = require("@openinc/parse-server-ldap");
  initLDAP(Parse);
};

module.exports.init = init;
```

## Configuration

1. Before using you should create a column (type string) in the **\_User** table in parse. The name of the column should be equal to `PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE`.
2. When using a docker environment and **docker-parse-server-opendash** you have to add a env variable to the docker compose for service **parse**
   - `OPENINC_PARSE_ADDITIONAL_PACKAGES: '@openinc/parse-server-ldap'`
   - Refer to https://github.com/open-inc/docker-parse-server-opendash
3. Add the env variables and volumes to load custom cloud code when running a docker environment
   - Add to environment section in **parse service**: `OPENINC_PARSE_CLOUDCODE_AUTOLOAD_DIR: './cloud-custom'`
   - Add to volumes section in **parse service**: `./cloud:/usr/src/app/cloud-custom`
4. Configuration is done using environment variables:
   - `PARSE_LDAP_FUNCTION_NAME` (default: "ldap_login") will be passed to `Parse.Cloud.define(PARSE_LDAP_FUNCTION_NAME)`
   - `PARSE_LDAP_URL` (default: "ldap://127.0.0.1:389") should be set to the LDAP server connection URL
   - `PARSE_LDAP_BASEPATH` should be set to a base path, i.e.: `"dc=example,dc=com"`
   - `PARSE_LDAP_LOGIN_BIND_DN` must be set to a DN which will identify the user, i.e.: `"uid=%user%,ou=Users,%basepath%"`.
     - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
     - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
     - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`

### Procedure of binding a user aka authenticating a user against ldap

Typically, users are authenticated (bind-method) using a service user. The service user searches for the username/email address provided by the login form, returns retrieved information, then the user is authenticated using the password. In most cases you want to map to the DN of a user. In this case, do not set `PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE` and `PARSE_LDAP_LOGIN_BIND_MAP_TO`. The following steps explain this process in detail:

1. The service user will bind to LDAP.
   - `PARSE_LDAP_SERVICE_USER_DN` DN for the service user
   - `PARSE_LDAP_SERVICE_USER_PW` PW for the service user
2. LDAP search will be executed.

   - `PARSE_LDAP_LOGIN_BIND_DN` as path
   - `PARSE_LDAP_LOGIN_BIND_MAP_FILTER` as filter (i.e.: `"(mail=%user%)"` or `(&(objectClass=user)(sAMAccountName=%user%))` or anything you want to filter about)
     - `%user%` will be replaced by the username the user entered
     - `%userWithoutDomain%` same as `%user%` but will strip the domain part, i.e.: `domain.com\username` will become `username`
     - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`

3. An output parameter will be selected from the first result.

   - `PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE` (default: "dn")

4. An attribute is selected from the output provided by the env variable.

   - `PARSE_LDAP_LOGIN_BIND_MAP_TO` (default: "%output%")
     - `%output%` will be replaced by the output parameter described above
     - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
     - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
     - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`

5. The new bind path will be used together with the password from the user to validate the login.

### User profile search

After binding the user, the user profile will be searched.
This is done by using `PARSE_LDAP_LOGIN_BIND_DN`.
If this will not work for you, you can search for the user within a DN with a given filter:

- `PARSE_LDAP_LOGIN_SEARCH_DN`
  - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
  - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
  - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`
- `PARSE_LDAP_LOGIN_SEARCH_FILTER`
  - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
  - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
  - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`

### Attributes used in Parse Server/LDAP

You can change which attributes from LDAP and which attributes in Parse will be used:

- `PARSE_LDAP_DN_ATTRIBUTE` (default: "dn") the attribute of the LDAP user, which will be used for the Parse user attribute, which will be defined with `PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE`
- `PARSE_LDAP_USERNAME_ATTRIBUTE` (default: "uid") the attribute of the LDAP user, which will be used for the Parse user `username` attribute
- `PARSE_LDAP_EMAIL_ATTRIBUTE` (default: "mail") the attribute of the LDAP user, which will be used for the Parse user `email` attribute
- `PARSE_LDAP_NAME_ATTRIBUTE` (default: "cn") the attribute of the LDAP user, which will be used for the Parse user `name` attribute
- `PARSE_LDAP_PARSE_LDAP_ATTRIBUTE` (default: "ldap") can be used to set the Parse user attribute, which will be used to identify users as LDAP users.
- `PARSE_LDAP_PARSE_LDAP_DN_ATTRIBUTE` (default: "ldap_dn") can be used to set the Parse user attribute, which will store the DN of the users.

### Restrict logins to members of a LDAP group

Optionally you can set a LDAP group to restrict, which users will be allowed to sign into Parse:

- `PARSE_LDAP_SERVICE_GROUP_DN` can be used to pass a DN to a group. Only users whos DN is in a `member` attribute of that group can login. Reading the group requires a service user..
- `PARSE_LDAP_SERVICE_USER_DN` DN for the service user
  - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`
- `PARSE_LDAP_SERVICE_USER_PW` PW for the service user
- `PARSE_LDAP_SERVICE_INTERVAL` can be used to pass a number in seconds, which will be used to start an interval in which all Parse users coming from LDAP will be validated as active LDAP users.

### Compatibility with @openinc/parse-server-opendash

- `PARSE_LDAP_UNIFY_CREDENTIALS` must be `"true"`, this will ensure that the same rules apply to the `username` and `email` fields as in the `@openinc/parse-server-opendash` package.
