# Deploying PowerAuth Server

This chapter explains how to deploy PowerAuth Server.

## Supported Databases

Following databases are supported:

- Oracle Database 11g, 12c, 19c, or 21c or
- PostgreSQL 9.5.4 or newer, or
- MySQL 5.5 or newer

Note that MSSQL database is not supported.

## Downloading PowerAuth Server WAR

You can download the latest `powerauth-java-server.war` at the [PowerAuth Server releases page](https://github.com/wultra/powerauth-server/releases).

## Adding Database Connector on Classpath

In order for the database connectivity to work, you need to add appropriate DB client libraries on your classpath.

For example, when using Oracle with Tomcat, make sure to add `ojdbc-${VERSION}.jar` to the `${CATALINA_HOME}/lib` folder (server restart will be required).

## Creating the Database Schema

In order for the PowerAuth Server to work, you need to have a correct schema in the database. To create the correct database schema, execute these SQL scripts for your database engine:

- [Oracle - Create Database Schema](./sql/oracle/create_schema.sql)
- [MySQL - Create Database Schema](./sql/mysql/create_schema.sql)
- [PostgreSQL - Create Database Schema](./sql/postgresql/create_schema.sql)

You can read more about PowerAuth Server database schema in following guide:

- [Database Structure](./Database-Structure.md)

## Connecting PowerAuth Server to Database

### Default Database Connectivity Parameters

The default database connectivity parameters in `powerauth-java-server.war` are following (PostgreSQL defaults):

```sh
spring.datasource.url=jdbc:postgresql://localhost:5432/powerauth
spring.datasource.username=powerauth
spring.datasource.password=
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.properties.hibernate.temp.use_jdbc_metadata_defaults=false
spring.jpa.hibernate.ddl-auto=none
spring.jpa.properties.hibernate.connection.characterEncoding=utf8
spring.jpa.properties.hibernate.connection.useUnicode=true
```

These parameters are of course only for the testing purposes, they are not suitable for production environment. They should be overridden for your production environment using a standard [Spring database connectivity related properties](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-sql.html#boot-features-connect-to-production-database).

### Oracle Connectivity Parameters

For Oracle database use following connectivity parameters (example):
```
spring.datasource.url=jdbc:oracle:thin:@//[HOST]:[PORT]/[SERVICENAME]
spring.datasource.username=powerauth
spring.datasource.password=*********
spring.datasource.driver-class-name=oracle.jdbc.driver.OracleDriver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.properties.hibernate.temp.use_jdbc_metadata_defaults=false
```

### PostgreSQL Connectivity Parameters

For PostgreSQL use following connectivity parameters (example):
```
spring.datasource.url=jdbc:postgresql://[HOST]:[PORT]/[DATABASE]
spring.datasource.username=powerauth
spring.datasource.password=*********
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.properties.hibernate.temp.use_jdbc_metadata_defaults=false
```

### Specifying Database Connection Character Set

The character set is defined when creating database and each database supports different character sets. 
In case of any national character issues, make sure to configure character encoding for database connection (example):
```
spring.jpa.properties.hibernate.connection.characterEncoding=utf8
spring.jpa.properties.hibernate.connection.useUnicode=true
```

## PowerAuth Server Configuration

_(optional)_ Optionally, you may set up following properties in order to configure your PowerAuth Server instance:

```sh
powerauth.service.applicationName=powerauth
powerauth.service.applicationDisplayName=PowerAuth Server
powerauth.service.applicationEnvironment=
```

These properties are returned when calling the `/rest/v3/status` method of the RESTful interface.

## Enabling PowerAuth Server Security

_(optional)_ By default, PowerAuth Server can be accessed by any application that can call the RESTful services. To change this behavior, you can set up a restricted access flag in the server configuration:

```sh
powerauth.service.restrictAccess=true # 'false' is default value
```

If the restricted access is enabled, PowerAuth Server uses credentials stored in `pa_integration` table to verify the access permission. Therefore, you must create a record for each application you that will integrate with PowerAuth Server.

```sql
INSERT INTO `powerauth`.`pa_integration` (`id`, `name`, `client_token`, `client_secret`)
    VALUES ("$(ID)", "$(NAME)", "$(CLIENT_TOKEN)", "$(CLIENT_SECRET)");
```

Values of `ID`, `CLIENT_TOKEN` and `CLIENT_SECRET` must be in UUID Level 4 format (for example `60586743-89d0-4689-b0fb-f4c597294b67`), `NAME` can be any name of the integration (for example, a name of the associated application).

<!-- begin box info --> 
The RESTful interface is secured using Basic HTTP Authentication (pre-emptive).
<!-- end -->

## Deploying PowerAuth Server WAR File

You can deploy PowerAuth Server WAR into any Java container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-java-server/` (Swagger is then available on `http://localhost:8080/powerauth-java-server/swagger-ui.html`).

To deploy PowerAuth Server to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

### Setting the Application Properties

There are generally two approaches to property configuration when deploying on the server:

#### 1. Configuring the Properties Directly

You can specify the individual properties directly in the server configuration. For example, on Tomcat, you can create an XML file called `${CATALINA_HOME}/conf/Catalina/localhost/powerauth-java-server.xml` with the following properties for database configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Context>
    <Parameter name="spring.datasource.url" value="jdbc:mysql://localhost:3306/powerauth"/>
    <Parameter name="spring.datasource.username" value="powerauth"/>
    <Parameter name="spring.datasource.password" value=""/>
    <Parameter name="spring.datasource.driver-class-name" value="com.mysql.jdbc.Driver"/>
    <Parameter name="spring.jpa.database-platform" value="org.hibernate.dialect.PostgreSQLDialect"/>
</Context>
```

#### 2. Configuring by Pointing to Configuration File

Alternatively, you can create a single property in the server configuration that only points to your custom configuration file `/path/to/some/custom.properties`. This method is especially useful in situations where the server configuration must be as simple as possible (for example, creating a configuration module in JBoss Wildfly). In such case, do not forget to also include the default `application.properties` file that is on the classpath by default (it is bundled inside the WAR). Here is the Tomcat example again: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Context>
    <Parameter name="spring.config.location" value="classpath:/application.properties,file:/path/to/some/custom.properties"/>
</Context>
```

To match the previous example, the contents of `/path/to/come/custom.properties` is the following:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/powerauth
spring.datasource.username=powerauth
spring.datasource.password=
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
```

## Generating Your First Application

In order to initialize the database with an application, call PowerAuth Server RESTful service endpoint:

```bash
$ curl -s -H "Content-Type: application/json" -X POST -d '{ "requestObject": { "applicationId": "DEMO-APPLICATION-NAME" } }' http://localhost:8080/powerauth-java-server/rest/v3/application/create | json_pp
{
   "status" : "OK",
   "responseObject" : {
      "applicationId" : "DEMO-APPLICATION-NAME"
   }
}
```

This command will create:

- A new application instance called "DEMO-APPLICATION-NAME".
- A default application version named "default" with associated `application_key` and `application_secret` values
- A new master key pair associated with the application.

To get the application details, you can copy the `applicationId` value from the previous response and call:

```bash
$ curl -s -H "Content-Type: application/json" -X POST -d '{ "requestObject": { "applicationId": "DEMO-APPLICATION-NAME" } }' http://localhost:8080/powerauth-java-server/rest/v3/application/detail | json_pp
{
   "status" : "OK",
   "responseObject" : {
      "applicationId" : "DEMO-APPLICATION-NAME",
      "masterPublicKey" : "BKOUTVjJKVB/AnRwq3tbqVkol6omI9DS6E/Yu3swh0l6MewONsjL01LA2/dxpgN5+6Ihy9cW1BpuYtdoFrxxlTA=",
      "versions" : [
         {
            "applicationVersionId" : "default",
            "applicationKey" : "zinbZhRMTXP4UTY+QrjZsg==",
            "applicationSecret" : "tzE7Ps0Ia8G/pFM75rh6yA==",
            "supported" : true
         }
      ]
   }
}
```

## Correlation Header Configuration (Optional)

You can enable correlation header logging in PowerAuth server by enabling the following properties:

```properties
powerauth.service.correlation-header.enabled=true
powerauth.service.correlation-header.name=X-Correlation-ID
powerauth.service.correlation-header.value.validation-regexp=[a-zA-Z0-9\\-]{8,1024}
logging.pattern.console=%clr(%d{${LOG_DATEFORMAT_PATTERN:yyyy-MM-dd HH:mm:ss.SSS}}){faint} %clr(${LOG_LEVEL_PATTERN:%5p}) [%X{X-Correlation-ID}] %clr(%5p) %clr(${PID: }){magenta} %clr(---){faint} %clr([%15.15t]){faint} %clr(%-40.40logger{39}){cyan} %clr(:){faint} %m%n${LOG_EXCEPTION_CONVERSION_WORD:%wEx}
```

Update the correlation header name in case you want to use a different HTTP header than `X-Correlation-ID`. You can also update the regular expression for correlation header value validation to match the exact format of correlation header value that will be used.

The logging pattern for console is the Spring default logging pattern with the addition of `%X{X-Correlation-ID}`. This variable is used to log the actual value of the correlation header.

For best traceability, the correlation headers should be enabled in the whole PowerAuth stack, so enable the correlation headers in other deployed applications, too. The configuration property names are the same in all PowerAuth applications: `powerauth.service.correlation-header.*`. The correlation header values are passed through the stack, so the requests can be traced easily across multiple components.  

## Troubleshooting

### Issues With Database Connectivity

Note that some database engines (for example MySQL) let you specify the default schema as a part of a URL. Other engines, for example **Oracle**, do not allow this. In order to specify the correct default schema, you need to use a following property:

```sh
spring.jpa.properties.hibernate.default_schema=powerauth
```

Some application servers, such as **WildFly** by JBoss, are very restrictive in class loading. As a result, you might get "Cannot load driver class: oracle.jdbc.driver.OracleDriver" errors despite the fact [the proper driver is on the server classpath](https://developer.jboss.org/wiki/DataSourceConfigurationInAS7). In order to workaround this issue in a clean fashion, you need to create a JNDI datasource (named for example `jdbc/powerauth`) and use it instead of JDBC properties - you must set these to empty values. This way, server smartly recognizes that the driver library must be loaded. To use JNDI configuration, set the system properties like so:

```sh
spring.datasource.url=
spring.datasource.username=
spring.datasource.password=
spring.datasource.driver-class-name=
spring.jpa.database-platform=
spring.jpa.hibernate.ddl-auto=none
spring.datasource.jndi-name=java:/jdbc/powerauth
```

### Deploying On JBoss / Wildfly

Follow the extra instructions in chapter [Deploying PowerAuth Server on JBoss / Wildfly](./Deploying-Wildfly.md).

### Issues With Bouncy Castle Provider

PowerAuth Server uses Bouncy Castle as a Java cryptography provider. If you encounter any issues that may point to an incorrectly installed cryptography provider, please follow our tutorial [how to configure Bouncy Castle](./Installing-Bouncy-Castle.md).

### How to Disable Display of Tomcat Version

It case you do not want to show Tomcat version on error pages when deploying PowerAuth server, you can use the following configuration:

- Edit the file `<install-directory>/conf/server.xml`.
- Search for the parameters `<Host name="..."/>`.
- Just below that line, insert the following parameters `<Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false"/>`.
- Restart Tomcat.

