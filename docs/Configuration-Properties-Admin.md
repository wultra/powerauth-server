# Admin Configuration Properties

The PowerAuth Admin application uses the following public configuration properties:


## PowerAuth Service Configuration

| Property                                            | Default                                            | Note                                                                                                    |
|-----------------------------------------------------|----------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| `powerauth.service.url`                             | `http://localhost:8080/powerauth-java-server/rest` | PowerAuth service REST API base URL.                                                                    | 
| `powerauth.service.security.clientToken`            | `_empty_`                                          | PowerAuth REST API authentication token.                                                                | 
| `powerauth.service.security.clientSecret`           | `_empty_`                                          | PowerAuth REST API authentication secret / password.                                                    |
| `powerauth.service.ssl.acceptInvalidSslCertificate` | `false`                                            | Flag indicating if connections using untrusted TLS certificate should be made to the PowerAuth Service. |


## PowerAuth Admin Service Configuration

| Property                                         | Default           | Note                                                 |
|--------------------------------------------------|-------------------|------------------------------------------------------|
| `powerauth.admin.service.applicationName`        | `powerauth-admin` | Application name exposed in status endpoint.         |
| `powerauth.admin.service.applicationDisplayName` | `PowerAuth Admin` | Application display name exposed in status endpoint. |
| `powerauth.admin.service.applicationEnvironment` | `_empty_`         | Application environment exposed in status endpoint.  |

## PowerAuth Admin LDAP Configuration

| Property                                           | Default   | Note                                                                                                                                                                                                                                                                                |
|----------------------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `powerauth.admin.security.method`                  | `_empty_` | Security method (`ldap` or `_empty_`).                                                                                                                                                                                                                                              |
| `powerauth.admin.security.ldap.userDNPatterns`     | `_empty_` | If your users are at a fixed location in the directory you can use this attribute to map directly to the DN. The value is a specific pattern used to build the user's DN, for example "uid={0},ou=people". The key "{0}" must be present and will be substituted with the username. |
| `powerauth.admin.security.ldap.userSearchBase`     | `_empty_` | Search base for user searches, only used with `userSearchFilter`.                                                                                                                                                                                                                   |
| `powerauth.admin.security.ldap.userSearchFilter`   | `_empty_` | The LDAP filter used to search for users, for example `(uid={0})`. The substituted parameter is the user's login name.                                                                                                                                                              |
| `powerauth.admin.security.ldap.groupSearchBase`    | `_empty_` | The search base for group membership searches.                                                                                                                                                                                                                                      |
| `powerauth.admin.security.ldap.groupSearchFilter`  | `_empty_` | The LDAP filter to search for groups. The substituted parameter is the DN of the user.                                                                                                                                                                                              |
| `powerauth.admin.security.ldap.groupRoleAttribute` | `_empty_` | Specifies the attribute name which contains the role name.                                                                                                                                                                                                                          |
| `powerauth.admin.security.ldap.url`                | `_empty_` | LDAP service URL.                                                                                                                                                                                                                                                                   |
| `powerauth.admin.security.ldap.port`               | `_empty_` | LDAP service port.                                                                                                                                                                                                                                                                  |
| `powerauth.admin.security.ldap.root`               | `_empty_` | Root suffix for the embedded LDAP server.                                                                                                                                                                                                                                           |
| `powerauth.admin.security.ldap.ldif`               | `_empty_` | Specifies an ldif to load at startup for an embedded LDAP server.                                                                                                                                                                                                                   |
| `powerauth.admin.security.ldap.managerDN`          | `_empty_` | Username (DN) of the "manager" user identity (i.e. "uid=admin,ou=system") which will be used to authenticate to a (non-embedded) LDAP server. If omitted, anonymous access will be used.                                                                                            |
| `powerauth.admin.security.ldap.managerPassword`    | `_empty_` | The password for the manager DN. This is required if the `managerDN` property is set.                                                                                                                                                                                               |


## Monitoring and Observability

The WAR file includes the `micrometer-registry-prometheus` dependency.
Discuss its configuration with the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/2.7.18/reference/html/actuator.html#actuator.metrics).
