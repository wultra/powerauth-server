# Setting Up Active Directory Authentication

PowerAuth Admin supports optional authentication using Active Directory. This option is disabled by default.

<!-- begin box warning -->
In case you are using Linux/Unix LDAP implementation, please follow the [separate documentation](./Setting-Up-LDAP-Authentication.md).
<!-- end -->

## Using Custom Active Directory Properties

In case you already have your own Active Directory server and you would like to use it as an authentication provider for PowerAuth Admin, you can configure all required properties. Namely, these properties are available for configuration:

```sh
# Enable Active Directory Authentication
powerauth.admin.security.method=active-directory

# Set Properties
powerauth.admin.security.activeDirectory.domain=wultra.com
powerauth.admin.security.activeDirectory.url=ldap://1.2.3.4:389
powerauth.admin.security.activeDirectory.root=dc=wultra,dc=com
powerauth.admin.security.activeDirectory.userSearchFilter=
```

These properties should be sufficient to configure all parameters required for an Active Directory based authentication.

## Restricting Authentication to a Groups

The default value for the `powerauth.admin.security.activeDirectory.userSearchFilter` property is:

```
(&(objectClass=user)(userPrincipalName={0}))
```

To customize the user lookup query, you can change the property to include custom value (the `{0}` will be replaced by the `username@domain`), for example:

```
powerauth.admin.security.activeDirectory.userSearchFilter=(&(objectClass=user)(userPrincipalName={0})(memberOf=CN=MyCustomGroup,CN=Users,DC=wultra,DC=com))
```
