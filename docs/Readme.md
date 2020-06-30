# PowerAuth Server Documentation

PowerAuth Server is a Java EE application (packaged as an executable WAR file) responsible for the PowerAuth server-side cryptography implementation and data persistence. It exposes SOAP and RESTful API for the integrating applications (not end-user applications!), such as the internet banking or mobile banking API.

## Deployment Tutorials

- [Deploying PowerAuth Server](./Deploying-PowerAuth-Server.md)
- [System Requirements](./System-Requirements.md)
- [Migration Instructions](./Migration-Instructions.md)

## Integration Tutorials

- [Introduction](./Using-SOAP-Service-Client.md)
- [Configuring REST Client (Spring)](./Configuring-REST-Client-for-Spring.md)
- [Configuring SOAP Client (Spring WS)](./Configuring-SOAP-Client-for-Spring.md)
- [Configuring SOAP Client (Axis2)](./Configuring-SOAP-Client-for-Axis2.md)
- [Axis 1 Support (deprecated)](./Axis-1-Support-Deprecated.md)

## Reference Manual

- [SOAP Interface Methods](./SOAP-Service-Methods.md)
- [PowerAuth Server Database Structure](./Database-Structure.md)
- [PowerAuth Server Error Codes](./Server-Error-Codes.md)

## Additional Topics

- [Encrypting DB Records](./Encrypting-Records-in-Database.md)
- [Offline Signatures](./Offline-Signatures.md)