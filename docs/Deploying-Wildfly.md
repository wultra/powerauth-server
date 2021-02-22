# Deploying on JBoss / Wildfly

## JBoss Deployment Descriptor 

PowerAuth server contains the following configuration in `jboss-deployment-structure.xml` file for JBoss:

```xml
<?xml version="1.0"?>
<jboss-deployment-structure xmlns="urn:jboss:deployment-structure:1.2">
    <deployment>
        <exclude-subsystems>
            <!-- disable the logging subsystem because the application manages its own logging independently -->
            <subsystem name="logging" />
        </exclude-subsystems>

        <dependencies>
            <module name="com.wultra.powerauth.server.conf" />
        </dependencies>
        <local-last value="true" />
    </deployment>
</jboss-deployment-structure>
```

The deployment descriptor requires configuration of the `com.wultra.powerauth.server.conf` module.

## JBoss Module for PowerAuth Server Configuration

Create a new module in `PATH_TO_JBOSS/modules/system/layers/base/com/wultra/powerauth/server/conf/main`.

The files described below should be added into this folder.

### Main Module Configuration

The `module.xml` configuration is used for module registration. It also adds resources from the module folder to classpath:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<module xmlns="urn:jboss:module:1.3" name="com.wultra.powerauth.server.conf">
    <resources>
        <resource-root path="." />
    </resources>
</module>
```

### Logging Configuration

Use the `logback.xml` file to configure logging, for example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration scan="true" scanPeriod="30 seconds">

    <property name="LOG_FILE_DIR" value="/var/log/powerauth" />
    <property name="LOG_FILE_NAME" value="powerauth-server" />
    <property name="INSTANCE_ID" value="${jboss.server.name}" />

    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>${LOG_FILE_DIR}/${LOG_FILE_NAME}-${INSTANCE_ID}.log</file>
        <immediateFlush>true</immediateFlush>
        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <fileNamePattern>${LOG_FILE_DIR}/${LOG_FILE_NAME}-${INSTANCE_ID}-%d{yyyy-MM-dd}-%i.log</fileNamePattern>
            <maxFileSize>10MB</maxFileSize>
            <maxHistory>5</maxHistory>
            <totalSizeCap>100MB</totalSizeCap>
        </rollingPolicy>
        <encoder>
            <charset>UTF-8</charset>
            <pattern>%d{ISO8601} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <logger name="com.wultra" level="INFO" />
    <logger name="io.getlime" level="INFO" />

    <root level="INFO">
        <appender-ref ref="FILE" />
    </root>
</configuration>
```

### Application Configuration

The `application-ext.properties` file is used to override default configuration properties, for example:

```
# Database Configuration - Oracle
spring.datasource.url=jdbc:oracle:thin:@//[host]:[port]/[servicename]
spring.datasource.username=powerauth
spring.datasource.password=powerauth
spring.datasource.driver-class-name=oracle.jdbc.driver.OracleDriver

# Application Service Configuration
powerauth.service.applicationEnvironment=TEST
```

PowerAuth Server Spring application uses the `ext` Spring profile which activates overriding of default properties by `application-ext.properties`. 

### Bouncy Castle Installation

The Bouncy Castle module for JBoss / Wildfly needs to be enabled as a global module for PowerAuth.

Follow the instructions in the [Installing Bouncy Castle](./Installing-Bouncy-Castle.md) chapter. 
Note that the instructions differ based on Java version and application server type.
