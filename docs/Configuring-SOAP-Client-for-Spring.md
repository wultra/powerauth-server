---
layout: page
title: Configuring SOAP Client for Spring WS
---

This tutorial shows the way internet banking (or other similar application) developers integrate with PowerAuth Server using a SOAP service client.

## Prerequisites For the Tutorial

- Running PowerAuth Server with available SOAP interface.
- Knowledge of Java EE applications based on Spring Framework.
- Software: IDE - Spring Tool Suite, Java EE Application Server (Pivotal Server, Tomcat, ...)

## Integration Manual

### Add a Maven Dependency

To add a PowerAuth SOAP service client support in your application, add Maven dependency for PowerAuth RESTful Client module in your `pom.xml` file:

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
		marshaller.setContextPath("io.getlime.powerauth.soap");
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

### Setting Up Credentials

_(optional)_ In case PowerAuth Server uses a [restricted access flag in the server configuration](https://github.com/lime-company/powerauth-server/wiki/Deploying-PowerAuth-Server#enabling-powerauth-20-server-security), you need to configure credentials for the WS-Security so that your client can connect to the SOAP service - modify your `PowerAuthWebServiceConfiguration` to include `Wss4jSecurityInterceptor` bean, like so:

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

## Using the SOAP Service Client

In order to use SOAP service client, follow our [generic SOAP client service documentation](./SOAP-Client-Library-Usage) and read the [reference manual](./SOAP-Service-Methods).
