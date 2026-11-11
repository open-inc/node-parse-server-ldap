# @openinc/parse-server-ldap

## Installation

```
pnpm i @openinc/parse-server-ldap
```

## Usage

This package is ESM-only. It cannot be loaded with `require()`.

Init the LDAP plugin in a js file that will be loaded by Cloud Code and pass the Parse instance of your Parse Server (the global `Parse` in Cloud Code). If no instance is passed, the plugin falls back to `globalThis.Parse`.

Example (ESM):

```js
import { init as initLDAP } from "@openinc/parse-server-ldap";

export const init = async () => {
  console.log("Init LDAP Plugin.");
  await initLDAP(Parse);
};
```

If your Cloud Code file is CommonJS, load the plugin with a dynamic `import()` instead of `require()`:

```js
const init = async () => {
  console.log("Init LDAP Plugin.");

  const { init: initLDAP } = await import("@openinc/parse-server-ldap");
  await initLDAP(Parse);
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
   - `PARSE_LDAP_LOGIN_SEARCH_SCOPE`: **You probably want to set this to 'sub'** otherwise only `PARSE_LDAP_LOGIN_BIND_DN` will be searched but not its subordinates
   - `PARSE_LDAP_FUNCTION_NAME` (default: "ldap_login") will be passed to `Parse.Cloud.define(PARSE_LDAP_FUNCTION_NAME)`
   - `PARSE_LDAP_URL` (default: "ldap://127.0.0.1:389") should be set to the LDAP server connection URL
   - `PARSE_LDAP_REJECT_UNAUTHORIZED` (default: "true") only applies to `ldaps://` URLs. The server certificate is validated by default. Set it to `"false"` to skip certificate validation (not recommended, only for testing).
   - `PARSE_LDAP_CA_FILE` (optional) path to the CA certificate(s) used to validate the server certificate of an `ldaps://` connection, i.e. your internal/AD CA. See [LDAPS with an internal CA](#ldaps-with-an-internal-ca).
   - `PARSE_LDAP_TIMEOUT` (default: "10") timeout in seconds for connecting to the LDAP server and for each LDAP operation.
   - StartTLS (`ldap://` upgraded to TLS) is not supported. Use `ldaps://` for encrypted connections.
   - `PARSE_LDAP_BASEPATH` should be set to a base path, i.e.: `"dc=example,dc=com"`
   - `PARSE_LDAP_LOGIN_BIND_DN` must be set to a DN which will identify the user, i.e.: `"uid=%user%,ou=Users,%basepath%"`.
     - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
     - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
     - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`

### LDAPS with an internal CA

LDAP servers (especially Active Directory) usually use a certificate issued by an internal CA, which Node.js does not trust by default. Since the server certificate is validated by default, you have to provide the CA certificate:

1. Export the root certificate of your internal CA (and the intermediate/issuing CA, if the LDAP server does not send it). Both PEM (Base64) and DER (binary `.cer`, the default export format on Windows) are supported. A PEM file may contain multiple certificates.
2. Make the file available to Parse Server and point `PARSE_LDAP_CA_FILE` to it, i.e. with docker compose for service **parse**:
   - volumes: `./certs/internal-ca.pem:/usr/src/app/certs/internal-ca.pem:ro`
   - environment: `PARSE_LDAP_URL: 'ldaps://dc01.example.local:636'` and `PARSE_LDAP_CA_FILE: '/usr/src/app/certs/internal-ca.pem'`
3. The host name in `PARSE_LDAP_URL` must match the certificate (CN/SAN). Use the DNS name of the LDAP server, not an IP address or a short name that is not part of the certificate.

If the CA file cannot be read, the plugin will not be activated. TLS errors during login (i.e. `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` or `ERR_TLS_CERT_ALTNAME_INVALID`) are logged by Parse Server, the client only receives `Invalid username/password.`.

Alternatively you can use the Node.js env `NODE_EXTRA_CA_CERTS` instead of `PARSE_LDAP_CA_FILE`.

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
