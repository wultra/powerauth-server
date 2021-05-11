# Configuring REST Client for Spring

This tutorial shows the way internet banking (or other similar application) developers integrate with PowerAuth Server using a REST client.

## Prerequisites For the Tutorial

- Running PowerAuth Server with available REST interface.
- Knowledge of web applications based on Spring Framework.
- Software: IDE, Application Server (Tomcat, Wildfly...)

## Integration Manual

### Add a Maven Dependency

To add a PowerAuth REST client support in your application, add Maven dependency for PowerAuth REST client module in your `pom.xml` file:

```xml
<dependency>
    <groupId>io.getlime.security</groupId>
    <artifactId>powerauth-rest-client-spring</artifactId>
    <version>${powerauth.version}</version>
</dependency>
```

### Configure PowerAuth REST Client

In order to connect to the correct PowerAuth Server, you need to add following configuration:

```java
@Configuration
@ComponentScan(basePackages = {"com.wultra.security.powerauth"})
public class PowerAuthClientConfiguration {

    @Value("${powerauth.rest.url}")
    private String powerAuthRestUrl;

    @Bean
    public PowerAuthClient powerAuthRestClient() {
        return new PowerAuthRestClient(powerAuthRestUrl);
    }

}
```

In case you need to configure the client, use:
```java
    @Bean
    public PowerAuthRestClient powerAuthRestClient() {
        PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
        config.setConnectTimeout(3000);
        ...
        return new PowerAuthRestClient(powerAuthRestUrl, config);
    }
```

The following REST client options are available:

- `maxMemorySize` - configures maximum memory size per request, default 1 MB
- `connectTimeout` - configures connection timeout, default 5000 ms
- `proxyEnabled` - enables proxy, disabled by default
- `proxyHost` - proxy hostname or IP address
- `proxyPort` - proxy server port
- `proxyUsername` - proxy username in case proxy authentication is required
- `proxyPassword` - proxy password in case proxy authentication is required
- `powerAuthClientToken` - client token for PowerAuth server authentication, used in case authentication is enabled on PowerAuth server
- `powerAuthClientSecret` - client secret for PowerAuth server authentication, used in case authentication is enabled on PowerAuth server
- `acceptInvalidSslCertificate` - whether SSL certificates should be validated, used during development

### Using the PowerAuth REST Client

In order to use a `PowerAuthServiceClient` instance, you can easily `@Autowire` it in your class, for example in your Spring MVC `@Controller`, like this:

```java
@Controller
@RequestMapping(value = "ib/settings")
public class AuthenticationController {

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

}
```
