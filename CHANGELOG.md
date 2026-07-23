# [1.0.0](https://github.com/open-inc/node-parse-server-ldap/compare/v0.7.0...v1.0.0) (2026-07-23)


* feat!: Repair build, drop CVE-carrying parse dependency, modernize release ([191067c](https://github.com/open-inc/node-parse-server-ldap/commit/191067c24a0b12b7a1ac1bde0b35b3757fc579a6))


### Bug Fixes

* Add npmrc ([579a724](https://github.com/open-inc/node-parse-server-ldap/commit/579a724a7036343fdf6eb3a11407fde1369f95b3))


### Features

* Repair build, drop CVE-carrying parse dependency, modernize release ([37166a0](https://github.com/open-inc/node-parse-server-ldap/commit/37166a0c14d011410fd5f939d4b42c0fbb8d9ca3))


### BREAKING CHANGES

* parse is now a peerDependency instead of a bundled dependency. Consumers must provide parse themselves (any Parse Server host already does). This also cuts the transitive ws vulnerabilities from the published package.
* parse is now a peerDependency instead of a bundled
dependency. Consumers must provide parse themselves (any Parse Server
host already does). This also cuts the transitive ws vulnerabilities
from the published package.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

# [0.7.0](https://github.com/open-inc/node-parse-server-ldap/compare/v0.6.8...v0.7.0) (2025-07-04)


### Bug Fixes

* ensure session token after signup ([164cf7f](https://github.com/open-inc/node-parse-server-ldap/commit/164cf7f0dc9c7158c032bf975f22066dda6e379b))


### Features

* introduce env variable for tls option rejectUnauthorized ([ce1422c](https://github.com/open-inc/node-parse-server-ldap/commit/ce1422c11ef66f80b7b24a7e56f14484ba3ce73c))
* set default tenant using env variable ([8e5b964](https://github.com/open-inc/node-parse-server-ldap/commit/8e5b9646696b6dc236e2a7007de57a76e6388bf7))

## [0.6.8](https://github.com/open-inc/node-parse-server-ldap/compare/v0.6.7...v0.6.8) (2025-06-04)


### Bug Fixes

* To trigger release ([fce5a17](https://github.com/open-inc/node-parse-server-ldap/commit/fce5a17e52ed31b3f1884237e10d7d344ec013c5))
