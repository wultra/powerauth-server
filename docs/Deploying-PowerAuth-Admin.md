# Deploying PowerAuth Admin

This chapter explains how to deploy PowerAuth Admin.

PowerAuth Admin is a web administration console for the [PowerAuth Server](https://github.com/wultra/powerauth-server).
It allows an easy application setup, an activation management and integration configurations.

<!-- begin box warning -->
Important note: Since PowerAuth Admin is a very simple application with direct access to the PowerAuth Server REST services, it must not be under any circumstances published publicly and must be constrained to the in-house closed infrastructure.
<!-- end -->

## Downloading PowerAuth Admin

You can download the latest `powerauth-admin.war` at the [PowerAuth Admin releases page](https://github.com/wultra/powerauth-admin/releases).

## Configuring PowerAuth Admin

The default implementation of a PowerAuth Admin has only one compulsory configuration parameter `powerauth.service.url` that configures the REST endpoint location of a PowerAuth Server. The default value for this property points to `localhost`:

```bash
powerauth.service.url=http://localhost:8080/powerauth-java-server/rest
```

## Setting Up REST Service Credentials

_(optional)_ In case PowerAuth Server uses a [restricted access flag in the server configuration](https://github.com/wultra/powerauth-server/blob/develop/docs/Deploying-PowerAuth-Server.md#enabling-powerauth-server-security), you need to configure credentials for the PowerAuth Admin so that it can connect to the REST service:

```sh
powerauth.service.security.clientToken=
powerauth.service.security.clientSecret=
```

The credentials are stored in the `pa_integration` table.

<!-- begin box info -->
Note: The RESTful interface is secured using Basic HTTP Authentication (pre-emptive).
<!-- end -->

## Disabling SSL Validation During Development

_(optional)_ While this is **strongly discouraged in production environment** (we cannot emphasize this enough), some development environments may use self-signed certificate for HTTPS communication. In case PowerAuth REST service uses HTTPS with such certificate, and in case you are not able to correctly configure a custom keystore in your server container, you may disable SSL certificate validation by setting this property:

```bash
powerauth.service.ssl.acceptInvalidSslCertificate=true
```

## Configuring Admin User Authentication

_(recommended)_ PowerAuth Admin supports optional authentication using the LDAP protocol. This option is disabled by default, but we recommend setting up LDAP based authentication at least for the production environment. Read more about how to setup LDAP Authentication in a separate chapter.

- [Setting Up LDAP Authentication](./Setting-Up-LDAP-Authentication.md)

## Deploying PowerAuth Admin

You can deploy PowerAuth Admin into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-admin/`.

To deploy PowerAuth Admin to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

Running PowerAuth Admin application from console using the `java -jar` command is not supported.

<!-- begin box warning -->
Important note: Since PowerAuth Admin is a very simple application with direct access to the PowerAuth Server REST services, it must not be under any circumstances published publicly and must be constrained to the in-house closed infrastructure.
<!-- end -->

## Deploying PowerAuth Admin On JBoss / Wildfly

Follow the extra instructions in chapter [Deploying PowerAuth Admin on JBoss / Wildfly](./Admin-Deploying-Wildfly.md).
