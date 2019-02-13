# Installing Bouncy Castle

In order to function correctly, PowerAuth software requires Bouncy Castle to be available.

Bouncy Castle library installation depends on Java version and used web container.

## Installing Bouncy Castle on Java 8

Bouncy Castle library is installed in two steps on Java 8:
- Bouncy Castle security provider needs to be configured in `java.security` configuration file.
- Java 8 provides a library extension mechanism which can be used to installed Bouncy Castle with exception of Wildfly which has it's own mechanism for installing Bouncy Castle.  

### Configuring Java Security for Java 8

Add following record to your `${JDK_HOME}/jre/lib/security/java.security`:

```sh
security.provider.N=org.bouncycastle.jce.provider.BouncyCastleProvider
```

... where `N` should be replaced according to your file content. Usually, there are multiple `security.provider.X` records in the file, you should chose the next in order number as `N`, for example:

```sh
#
# List of providers and their preference orders (see above):
#
security.provider.1=sun.security.provider.Sun
security.provider.2=sun.security.rsa.SunRsaSign
security.provider.3=sun.security.ec.SunEC
security.provider.4=com.sun.net.ssl.internal.ssl.Provider
security.provider.5=com.sun.crypto.provider.SunJCE
security.provider.6=sun.security.jgss.SunProvider
security.provider.7=com.sun.security.sasl.Provider
security.provider.8=org.jcp.xml.dsig.internal.dom.XMLDSigRI
security.provider.9=sun.security.smartcardio.SunPCSC
security.provider.10=apple.security.AppleProvider
security.provider.11=org.bouncycastle.jce.provider.BouncyCastleProvider
```

_Warning: Configuring Bouncy Castle as the first provider (security.provider.1) may cause JVM errors._

### Installing Bouncy Castle - Tomcat on Java 8

Copy [`bcprov-jdk15on-[VERSION].jar`](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on) to your `${JDK_HOME}/jre/lib/ext` folder.

You can get the Bouncy Castle provider here:
https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on

### Installing Bouncy Castle - Wildfly on Java 8

In order to make PowerAuth Server work on Wildfly, you need to enable the Bouncy Castle module on the server, by adding the `<global-modules>` element in the `standalone.xml` file:

```xml
<subsystem xmlns="urn:jboss:domain:ee:4.0">
    <!-- ... -->
    <global-modules>
        <module name="org.bouncycastle" slot="main"/>
    </global-modules>
</subsystem>
```

Note that when Wildfly's Bouncy Castle module is used, Bouncy Castle should not be present in the `lib/ext` folder of the Java runtime, otherwise the following error can occur: `key spec not recognized` due to clash of Bouncy Castle libraries.

### Testing Bouncy Castle Installation on Java 8

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

## Installing Bouncy Castle on Java 11

Bouncy Castle library is installed in two steps on Java 11:
- Bouncy Castle security provider needs to be configured in `java.security` configuration file.
- Java 11 no longer provides a library extension mechanism and thus Bouncy Castle library must be installed in the web container.

### Configuring Java Security for Java 11

Add following record to your `${JDK_HOME}/conf/security/java.security`:

```sh
security.provider.N=org.bouncycastle.jce.provider.BouncyCastleProvider
```

... where `N` should be replaced according to your file content. Usually, there are multiple `security.provider.X` records in the file, you should chose the next in order number as `N`, for example:

```sh
#
# List of providers and their preference orders (see above):
#
security.provider.1=SUN
security.provider.2=SunRsaSign
security.provider.3=SunEC
security.provider.4=SunJSSE
security.provider.5=SunJCE
security.provider.6=SunJGSS
security.provider.7=SunSASL
security.provider.8=XMLDSig
security.provider.9=SunPCSC
security.provider.10=JdkLDAP
security.provider.11=JdkSASL
security.provider.12=Apple
security.provider.13=SunPKCS11
security.provider.14=org.bouncycastle.jce.provider.BouncyCastleProvider
```

_Warning: Configuring Bouncy Castle as the first provider (security.provider.1) may cause JVM errors._

### Installing Bouncy Castle - Tomcat on Java 8

Copy [`bcprov-jdk15on-[VERSION].jar`](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on) to your `${CATALINA_HOME}/lib` folder.

You can get the Bouncy Castle provider here:
https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on

### Installing Bouncy Castle - Wildfly on Java 11

In order to make PowerAuth Server work on Wildfly, you need to enable the Bouncy Castle module on the server, by adding the `<global-modules>` element in the `standalone.xml` file:

```xml
<subsystem xmlns="urn:jboss:domain:ee:4.0">
    <!-- ... -->
    <global-modules>
        <module name="org.bouncycastle" slot="main"/>
    </global-modules>
</subsystem>
```

### Testing Bouncy Castle Installation on Java 11

You can test the installation in web container using our simple [bc-check.war application](https://github.com/wultra/powerauth-crypto/releases/download/0.21.0/check-bc.war).

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

## Troubleshooting Bouncy Castle Installation Issues

In case you get the following error: `key spec not recognized`, there are possible issues:

- Tomcat on Java 8: Check that Bouncy Castle library is installed in `${JDK_HOME}/jre/lib/ext` and it is not present in `${CATALINA_HOME}/lib`.
- Tomcat on Java 11: Check that Bouncy Castle library is installed in `${CATALINA_HOME}/lib`.
- Wildfly on Java 8: Check that Bouncy Castle library is not installed in `${JDK_HOME}/jre/lib/ext` and it is installed as a module in Wildfly.
- Wildfly on Java 11: Check that Bouncy Castle library is installed as a module in Wildfly.
- All containers on Java 8/11: Check that none of the deployed war files contains Bouncy Castle library, it would clash with the globally installed version of the library. This rule applies only for PowerAuth `2019.04` or later.
