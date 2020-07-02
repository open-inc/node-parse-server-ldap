# @openinc/parse-server-ldap

## Installation

```
npm i @openinc/parse-server-ldap
```

## Usage

In your Cloud Code entry file:

```js
const initLDAP = require("@openinc/parse-server-ldap");

initLDAP(Parse);
```

## Configuration

Configuration is done using environment variables:

- `PARSE_LDAP_ACTIVE` (default: "true") can be set to `"false"` to disable the plugin.
- `PARSE_LDAP_FUNCTION_NAME` (default: "ldap_login") will be passed to `Parse.Cloud.define(PARSE_LDAP_FUNCTION_NAME)`
- `PARSE_LDAP_URL` (default: "ldap://127.0.0.1:389") should be set to the LDAP server connection URL
- `PARSE_LDAP_BASEPATH` should be set to a base path, i.e.: `"dc=example,dc=com"`
- `PARSE_LDAP_LOGIN_BIND_DN` must be set to a DN which will identify the user, i.e.: `"uid=%user%,ou=Users,%basepath%"`.
  - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
  - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
  - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`

### Bind DN mapping

Optionally you can map the bind DN to another using a service user. Lets say the user want's to login with an email, but bind will only support login by DN. The mapping is done in a couple of steps:

1. The service user will bind to ldap
2. A search will be performed, using `PARSE_LDAP_LOGIN_BIND_DN` as a path and `PARSE_LDAP_LOGIN_BIND_MAP_FILTER` as a filter.
3. An output parameter will be selected from the first result using `PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE`
4. The output paramter will be passed to `PARSE_LDAP_LOGIN_BIND_MAP_TO` to create a new bind path.
5. The new bind path will be used together with the password from the user to validate the login

- `PARSE_LDAP_LOGIN_BIND_MAP_FILTER` must be set to perform a bind DN mapping, i.e.: `"(mail=%user%)"`.
  - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
  - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
  - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`
- `PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE` (default: "dn") can be set to perform a bind DN mapping.
- `PARSE_LDAP_LOGIN_BIND_MAP_TO` (default: "%output%") can be set to perform a bind DN mapping.
  - `%output%` will be replaced by output parameter described above
  - `%user%` will be replaced by the username the user is providing to the Cloud Code Function
  - `%userWithoutDomain%` same as `%user%`, but will strip the domain part, i.e.: `domain.com\username` will become `username`
  - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`
- `PARSE_LDAP_SERVICE_USER_DN` DN for the service user
  - `%basepath%` will be replaced by the value of `PARSE_LDAP_BASEPATH`
- `PARSE_LDAP_SERVICE_USER_PW` PW for the service user

In most cases you want to map to the DN of an user. In this case do not set `PARSE_LDAP_LOGIN_BIND_MAP_ATTRIBUTE` and `PARSE_LDAP_LOGIN_BIND_MAP_TO`.

### User profile search

After binding the user, the user profile will be searched. This is done by using `PARSE_LDAP_LOGIN_BIND_DN`. If this will not work for you, you can search for the user within a DN with a given filter:

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
- `PARSE_LDAP_SERVICE_INTERVAL` can be used to pass a number in milliseconds, which will be used to start an interval in which all Parse users coming from LDAP will be validated as active LDAP users.
