# Installing Bouncy Castle

In order to function correctly, PowerAuth software requires Bouncy Castle to be available.

Bouncy Castle library installation depends on Java version and used web container.

PowerAuth server uses dynamic initialization of Bouncy Castle provider, so it is not required to configure security provider statically in the Java Runtime configuration.

You can get the Bouncy Castle provider here:
https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on

## Installing on Java 11

Java 11 no longer provides a library extension mechanism and thus Bouncy Castle library must be installed in the web container.

### Bouncy Castle on Tomcat

Copy [`bcprov-jdk15on-167.jar`](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on) to your `${CATALINA_HOME}/lib` folder.

_Warning: Bouncy Castle library will not work properly in case any war file deployed to Tomcat contains another copy of the Bouncy Castle library, even if the war file is not related to PowerAuth.
Bouncy Castle library must be only present in the `${CATALINA_HOME}/lib` folder. The `key spec not recognized` error message will appear in Tomcat log in this case._

### Bouncy Castle on JBoss / Wildfly

PowerAuth server requires a specific version of Bouncy Castle library: `bcprov-jdk15on-167.jar`

In order to make PowerAuth Server work on JBoss / Wildfly, you need to add and enable the external Bouncy Castle module on the server
by adding the `<global-modules>` element in the `standalone.xml` file:

```xml
<subsystem xmlns="urn:jboss:domain:ee:4.0">
    <global-modules>
        <module name="org.bouncycastle.external" slot="main"/>
    </global-modules>
</subsystem>
```

The module should be defined using a new module XML file in JBoss folder `modules/system/layers/base/org/bouncycastle/external/main`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<module name="org.bouncycastle.external" xmlns="urn:jboss:module:1.8">
    <resources>
        <resource-root path="bcprov-jdk15on-167.jar"/>
    </resources>
</module>
```

Finally, copy the Bouncy Castle library `bcprov-jdk15on-167.jar` into folder  `modules/system/layers/base/org/bouncycastle/external/main` so that it is available for the module.

_Warning: do not reuse Bouncy Castle module `org.bouncycastle` from JBoss, because version of library provided by JBoss may differ from version required by PowerAuth._  

### Testing the Installation

You can test the installation in web container using our simple [bc-check.war application](https://github.com/wultra/powerauth-crypto/releases/download/0.23.0/check-bc.war).

The application performs following checks after startup:
- Check whether BC provider is correctly installed.
- Generate an ECSDA keypair.
- Compute and validate an ECSDA signature.

Once you deploy the application to the web container, you should see following messages in container log:
```
BC provider is installed.
ECSDA signature validation succeeded.
```

In case of any error or different output, please check the troubleshooting guide below.

## Installing on Java 8

Java 8 provides a library extension mechanism which can be used to installed Bouncy Castle with exception of JBoss / Wildfly which has it's own mechanism for installing Bouncy Castle.  

### Bouncy Castle on Tomcat

#### Standalone Tomcat

When running a standalone Tomcat instance, all you need to do is to copy [`bcprov-jdk15on-167.jar`](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on) to your `${JDK_HOME}/jre/lib/ext` folder.

#### Embedded Tomcat

In case you are running Spring Boot application with the embedded Tomcat server, you also might need to register the provider in the Java security configuration file. To do this, add a new line to `$JAVA_HOME/jre/lib/security/java.security` and enable Bouncy Castle security provider on a system level:

```
security.provider.N=org.bouncycastle.jce.provider.BouncyCastleProvider
```

Make sure to add the provider to the top of the list (ideally, N=2).

### Bouncy Castle on JBoss / Wildfly

PowerAuth server requires a specific version of Bouncy Castle library: `bcprov-jdk15on-167.jar`

In order to make PowerAuth Server work on JBoss / Wildfly, you need to add and enable the external Bouncy Castle module on the server
by adding the `<global-modules>` element in the `standalone.xml` file:

```xml
<subsystem xmlns="urn:jboss:domain:ee:4.0">
    <global-modules>
        <module name="org.bouncycastle.external" slot="main"/>
    </global-modules>
</subsystem>
```

The module should be defined using a new module XML file in JBoss folder `modules/system/layers/base/org/bouncycastle/external/main`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<module name="org.bouncycastle.external" xmlns="urn:jboss:module:1.8">
    <resources>
        <resource-root path="bcprov-jdk15on-167.jar"/>
    </resources>
</module>
```

Finally, copy the Bouncy Castle library `bcprov-jdk15on-167.jar` into folder  `modules/system/layers/base/org/bouncycastle/external/main` so that it is available for the module.

_Warning: do not reuse Bouncy Castle module `org.bouncycastle` from JBoss, because version of library provided by JBoss may differ from version required by PowerAuth._  

Note that when Bouncy Castle module for JBoss / Wildfly is used, Bouncy Castle should not be present in the `lib/ext` folder of the Java runtime, otherwise the following error can occur: `key spec not recognized` due to clash of Bouncy Castle libraries.

### Testing the Installation

You can test the installation using our [simple Java utility](./util/check-bc.jar):

```sh
$ java -jar check-bc.jar
```

The utility uses following source code to check the provider installation:

```java
import java.security.Security;

public class SimpleTest
{
    public static void main(String[] args)
    {
        String name = "BC";
        if (Security.getProvider(name) == null)
        {
            System.out.println("not installed");
        }
        else
        {
            System.out.println("installed");
        }
    }
}
```

## Troubleshooting Bouncy Castle Installation Issues

In case you get the following error: `key spec not recognized`, there are possible issues:

- Tomcat on Java 11: Check that Bouncy Castle library is installed in `${CATALINA_HOME}/lib`.
- Tomcat on Java 8: Check that Bouncy Castle library is installed in `${JDK_HOME}/jre/lib/ext` and it is not present in `${CATALINA_HOME}/lib`.
- JBoss / Wildfly on Java 11: Check that Bouncy Castle library is installed as a module in JBoss / Wildfly.
- JBoss / Wildfly on Java 8: Check that Bouncy Castle library is not installed in `${JDK_HOME}/jre/lib/ext` and it is installed as an external module in JBoss / Wildfly.
- All containers on Java 8/11: Check that none of the deployed war files contains Bouncy Castle library, even if the war file is not related to PowerAuth.
Another copy of Bouncy Castle library would clash with the globally installed version of the library. This rule applies only for PowerAuth `2019.05` or later.
