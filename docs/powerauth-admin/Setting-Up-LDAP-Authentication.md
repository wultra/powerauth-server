# Setting Up LDAP Authentication

PowerAuth Admin supports optional authentication using the LDAP protocol. This option is disabled by default, but we recommend setting up LDAP based authentication at least for the production environment.

## Enabling LDAP Authentication

To enable LDAP authentication, set following property:

```sh
powerauth.admin.security.method=ldap
```

## Using Simple File-Based LDAP Directory (LDIF)

You can use a simple file-based LDAP directory for PowerAuth Admin authentication, in case your organization does not use LDAP or in case you would like to keep PowerAuth Admin users completely separated from your other LDAP users. This mechanism uses Spring Security to start an [embedded LDAP Server](http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#using-an-embedded-test-server).

First, create an LDIF file `${LDIF_LOCATION}/admins.ldif` (replace `${LDIF_LOCATION}` with desired file location) with following content:

```
dn: ou=groups,dc=powerauth,dc=com
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=people,dc=powerauth,dc=com
objectclass: top
objectclass: organizationalUnit
ou: people

dn: uid=admin,ou=people,dc=powerauth,dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: PowerAuth Admin
sn: admin
uid: admin
userPassword: admin

dn: cn=admins,ou=groups,dc=powerauth,dc=com
objectclass: top
objectclass: groupOfUniqueNames
cn: admins
ou: admin
uniqueMember: uid=admin,ou=people,dc=powerauth,dc=com
```

This simple LDIF file defines an admin user called "admin" with password "admin" (under `com/powerauth` root). Of course, you may add as many users are you would like to and change the domain to any value that matches your organization.

In this example, we store password in the plain-text to LDIF file. This is mostly OK in a real world scenarios - in most cases, only the organization super admins are allowed to access the files anyway. But of course, we recommend setting a custom password and use `{SSHA256}` or similar algorithm to compute a salted password hash to store the passwords more securely.

Now, you need to specify attributes that tell PowerAuth Admin to look for the users at the right place:

```sh
# Enable LDAP Authentication
powerauth.admin.security.method=ldap

# Set Properties
powerauth.admin.security.ldap.userDNPatterns=uid={0},ou=people
powerauth.admin.security.ldap.groupSearchBase=ou=groups
powerauth.admin.security.ldap.root=dc=powerauth,dc=com
powerauth.admin.security.ldap.ldif=file:${LDIF_LOCATION}/admins.ldif
```

Don't forget to replace the `${LDIF_LOCATION}` with a correct path to the `admins.ldif` file.

Now, simply restart the application server and when you attempt to visit the PowerAuth Admin, you will be prompted for login credentials.

## Using Custom LDAP Properties

In case you already have your own LDAP server and you would like to use it as an authentication provider for PowerAuth Admin, you can configure all required properties. Namely, these properties are available for configuration:

```sh
# Enable LDAP Authentication
powerauth.admin.security.method=ldap

# Set Properties
powerauth.admin.security.ldap.userDNPatterns=
powerauth.admin.security.ldap.userSearchBase=
powerauth.admin.security.ldap.userSearchFilter=
powerauth.admin.security.ldap.groupSearchBase=
powerauth.admin.security.ldap.groupSearchFilter=
powerauth.admin.security.ldap.groupRoleAttribute=
powerauth.admin.security.ldap.url=
powerauth.admin.security.ldap.port=
powerauth.admin.security.ldap.root=
powerauth.admin.security.ldap.ldif=
powerauth.admin.security.ldap.managerDN=
powerauth.admin.security.ldap.managerPassword=
```

These properties should be sufficient to configure all parameters required for an LDAP based authentication.
