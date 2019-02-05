# Installing Bouncy Castle

In order to function correctly, PowerAuth software requires Bouncy Castle to be available. While some servers, such as Wildfly, already come with own BC version, other servers, for example Tomcat, requires BC to be installed system-wide. You also need to install BC for testing the server via our command-line utility.

## Java 8

You can install Bouncy Castle in your system by:

1. Copying [`bcprov-jdk15on-[VERSION].jar`](https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on) to your `${JDK_HOME}/jre/lib/ext` folder.
2. Adding a following record to your `${JDK_HOME}/jre/lib/security/java.security`:

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

You can get the Bouncy Castle provider here:
https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on

## Testing BC Installation

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
