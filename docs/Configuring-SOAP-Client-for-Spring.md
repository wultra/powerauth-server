# Configuring SOAP Client for Spring WS

This tutorial shows the way internet banking (or other similar application) developers integrate with PowerAuth Server using a SOAP service client.

## Prerequisites For the Tutorial

- Running PowerAuth Server with available SOAP interface.
- Knowledge of web applications based on Spring Framework.
- Software: IDE, Application Server (Tomcat, Wildfly...)

## Integration Manual

### Add a Maven Dependency

To add a PowerAuth SOAP service client support in your application, add Maven dependency for PowerAuth SOAP client module in your `pom.xml` file:

```xml
<dependency>
    <groupId>io.getlime.security</groupId>
    <artifactId>powerauth-java-client-spring</artifactId>
    <version>${powerauth.version}</version>
</dependency>
```

### Configure PowerAuth SOAP Service Client

In order to connect to the correct PowerAuth Server, you need to add following configuration:

```java
@Configuration
@ComponentScan(basePackages = {"io.getlime.security.powerauth"})
public class PowerAuthWebServiceConfiguration {

    @Value("${powerauth.service.url}")
    private String powerAuthServiceUrl;

    @Bean
    public Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPath("com.wultra.security.powerauth.client.v3");
        return marshaller;
    }

    @Bean
    public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
        PowerAuthServiceClient client = new PowerAuthServiceClient();
        client.setDefaultUri(powerAuthServiceUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        return client;
    }
}
```

_Note: The `v3` endpoints provide the most current implementation of PowerAuth cryptography protocol. If you still need to use the `v2` endpoints, include the `v2` context path for the Marshaller:_

```
marshaller.setContextPaths("com.wultra.security.powerauth.client.v2", "com.wultra.security.powerauth.client.v3");
```

### Setting Up Credentials

_(optional)_ In case PowerAuth Server uses a [restricted access flag in the server configuration](./Deploying-PowerAuth-Server.md#enabling-powerauth-server-security), you need to configure credentials for the WS-Security so that your client can connect to the SOAP service - modify your `PowerAuthWebServiceConfiguration` to include `Wss4jSecurityInterceptor` bean, like so:

```java
@Value("${powerauth.service.security.clientToken}")
private String clientToken;

@Value("${powerauth.service.security.clientSecret}")
private String clientSecret;

@Bean
public Wss4jSecurityInterceptor securityInterceptor(){
    Wss4jSecurityInterceptor wss4jSecurityInterceptor = new Wss4jSecurityInterceptor();
    wss4jSecurityInterceptor.setSecurementActions("UsernameToken");
    wss4jSecurityInterceptor.setSecurementUsername(clientToken);
    wss4jSecurityInterceptor.setSecurementPassword(clientSecret);
    wss4jSecurityInterceptor.setSecurementPasswordType(WSConstants.PW_TEXT);
    return wss4jSecurityInterceptor;
}

// ...

@Bean
public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
    PowerAuthServiceClient client = new PowerAuthServiceClient();
    client.setDefaultUri(powerAuthServiceUrl);
    client.setMarshaller(marshaller);
    client.setUnmarshaller(marshaller);

    // ****
    // HERE ==> Add interceptors for the security
    // ****
    ClientInterceptor interceptor = securityInterceptor();
    client.setInterceptors(new ClientInterceptor[] { interceptor });
    return client;
}
```

_Note: Make sure to use WSS4J, not WSS4J2 - this newer implementation still has couple serious issues._

_Note: For SOAP interface, PowerAuth Server uses WS-Security, `UsernameToken` validation (plain text password). The RESTful interface is secured using Basic HTTP Authentication (pre-emptive)._

### Using the PowerAuth SOAP Client

In order to use a `PowerAuthServiceClient` instance, you can easily `@Autowire` it in your class, for example in your Spring MVC `@Controller`, like this:

```java
@Controller
@RequestMapping(value = "ib/settings")
public class AuthenticationController {

    @Autowired
    private PowerAuthServiceClient powerAuthServiceClient;

    // ... Controller code

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
