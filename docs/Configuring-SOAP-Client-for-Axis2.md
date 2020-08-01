# Configuring SOAP Client for Axis2

This tutorial shows the way internet banking (or other "master front-end application") developers integrate with PowerAuth Server.

## Prerequisites For the Tutorial

- Running PowerAuth Server with available SOAP interface.
- Knowledge of web applications based on JAX-RS.
- Software: IDE, Application Server (Tomcat, Wildfly...)

## Integration Manual

### Add a Maven Dependency

To add a PowerAuth support in your application, add Maven dependency for PowerAuth SOAP client module in your `pom.xml` file:

```xml
<dependency>
    <groupId>io.getlime.security</groupId>
    <artifactId>powerauth-java-client-axis</artifactId>
    <version>${powerauth.version}</version>
</dependency>
```

### Configure PowerAuth SOAP Service Client

In order to connect to the correct PowerAuth Server, you need to add following producer class:

```java
@Dependent
public class PowerAuthBeanFactory {

    @Produces
    public PowerAuthServiceClient buildClient() {
        try {
            return new PowerAuthServiceClient("http://localhost:8080/powerauth-java-server/soap");
        } catch (AxisFault axisFault) {
            return null;
        }
    }

}
```

Make sure to set the correct path to the PowerAuth Server SOAP endpoint.

### Setting Up Credentials

//TODO: Describe SOAP client WS-Security configuration

_Note: For SOAP interface, PowerAuth Server uses WS-Security, `UsernameToken` validation (plain text password). The RESTful interface is secured using Basic HTTP Authentication (pre-emptive)._

### Using the PowerAuth SOAP Client

In order to use a `PowerAuthServiceClient` instance, you can easily `@Inject` it in your class, for example in your resource class, like this:

```java
@Path(value = "ib/settings")
public class IBSettingsResource {

    @Inject
    private PowerAuthServiceClient powerAuthServiceClient;

    // ... Resource code

}
```

### PowerAuth Protocol Compatibility

The SOAP client supports two versions of PowerAuth protocol:
- The version `3` methods are available as default implementation directly on the client class.
- You can access the version `2` specific methods using the `v2()` method in the client. This method will be deprecated in a future release.

You can access the WSDL files in following URLs:
- version `3`: http://localhost:8080/powerauth-java-server/soap/serviceV3.wsdl
- version `2`: http://localhost:8080/powerauth-java-server/soap/serviceV2.wsdl

## Using the SOAP Service Client

In order to use SOAP service client, follow our [generic SOAP client service documentation](./SOAP-Client-Library-Usage.md) and read the [reference manual](./SOAP-Service-Methods.md).
