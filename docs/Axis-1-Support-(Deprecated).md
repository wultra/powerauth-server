---
layout: page
title: Axis1 Support
---

In case you need to use Axis 1 for connecting to PowerAuth Server SOAP service, you are basically on your own. We do not have ready to use integration libraries and we do not plan to ever implement them. However, we have some observations from customers like you that can help you make the integration quickly.

### Adding WS-Security Headers

In case you use Axis 1 generated Stub and you need to add WS-Security header for `UsernameToken` authentication, you need to build the SOAP header yourself manually. This is due to the fact that libraries that provide WS-Security implementation for Axis 1 are in a very rusty shape.

Unfortunately, the default implementation of SOAP header elements in Axis 1 is bugy and not compliant with the SOAP service provided by PowerAuth Server. As a result, you need to modify the default behavior in following way:

- Add method `addSecurityHeader` that decorates `org.apache.axis.client.Stub` instance by the correct header:
    - Prepare elements with `UsernameToken`, `Username` and `Password`.
    - Make sure that `Password` element has `Type` attribute.
    - Override setter `setAttribute` of `SOAPHeaderElement` (in ad-hoc overriden class instance) so that it does not set the `soapenv:actor` attribute that causes problem when calling Spring WS SOAP service.
- Call `addSecurityHeader` on provided SOAP service `Port` instance.

Here is a gist of the implementation:

```java

// Prepare constants, so that you do not randomly place them in code
private static String QNAME = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
private static String SECURITY_HEADER = "Security";
private static String USERNAME_TOKEN = "UsernameToken";
private static String USERNAME = "Username";
private static String PASSWORD = "Password";
private static String PASSWORD_TYPE = "Type";
private static String PASSWORD_TYPE_URL = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";

/**
 * Add correct WS-Security header for UsernameToken authentication to provided SOAP service stub.
 * @param stub SOAP Service Stub.
 * @param username Username for authentication.
 * @param password Password for authentication.
 * @throws SOAPException in case there is an error building the SOAP element tree.
 */
private void addSecurityHeader(Stub stub, String username, String password) throws SOAPException {

    // Create anonymous subclass of SOAPHeaderElement, adding credentials, overriding
    // setAttribute method to avoid adding 'soapenv:actor' attribute and setting 'mustUnderstand'
    // attribute to true.
    SOAPHeaderElement wssHeader = new SOAPHeaderElement(new QName(QNAME, SECURITY_HEADER)) {

        {
            SOAPElement utElem = addChildElement(USERNAME_TOKEN);
            MessageElement usernameElement = (MessageElement )utElem.addChildElement(USERNAME);
            usernameElement.setValue(username);
            MessageElement passwordElement = (MessageElement) utElem.addChildElement(PASSWORD);
            passwordElement.setAttribute(PASSWORD_TYPE, PASSWORD_TYPE_URL);
            passwordElement.setValue(password);
        }

        @Override
        public void setAttribute(String namespace, String localName, String value) {
            if (!Constants.ATTR_ACTOR.equals(localName)) { // disallow setting actor attribute
                super.setAttribute(namespace, localName, value);
            }
        }
    }
    AtomicReference<SOAPHeaderElement> header = new AtomicReference<>(wssHeader);
    SOAPHeaderElement soapHeaderElement = header.get();
    soapHeaderElement.setMustUnderstand(true);
    soapHeaderElement.setActor(null);
    stub.setHeader(soapHeaderElement);
}

// Getter for the PowerAuthPort SOAP service port calls 'addSecurityHeader' to
// decorate default port implementation with correct SOAP header.
public PowerAuthPort getPowerAuthPort(Url url) throws PowerAuthException {
    try {
        PowerAuthPortServiceLocator locator = new PowerAuthPortServiceLocator();
        PowerAuthPort port = locator.getPowerAuthPortSoap11(url);
        addSecurityHeader((Stub) port, powerauthUsername, powerauthPassword );
        return port;
    } catch (SOAPException e) {
        // SOAP Exception
    } catch (ServiceException e) {
        // Service Exception
    }
}
```
