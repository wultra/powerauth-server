/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.getlime.security.powerauth.app.server.configuration;

import io.getlime.security.powerauth.app.server.service.exceptions.ActivationRecoveryException;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.exceptions.SoapFaultExceptionResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.security.wss4j2.Wss4jSecurityInterceptor;
import org.springframework.ws.soap.security.wss4j2.callback.SpringSecurityPasswordValidationCallbackHandler;
import org.springframework.ws.soap.server.endpoint.SoapFaultDefinition;
import org.springframework.ws.soap.server.endpoint.SoapFaultMappingExceptionResolver;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition;
import org.springframework.xml.xsd.SimpleXsdSchema;
import org.springframework.xml.xsd.XsdSchema;

import java.util.List;
import java.util.Properties;

/**
 * PowerAuth Server default web service configuration. Configures both basic endpoint information
 * (service, port, xsd) and security (WS-Security, with UsernameToken authentication) in case it is
 * enabled in application configuration ("powerauth.service.restrictAccess").
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@EnableWs
@Configuration
public class WebServiceConfig extends WsConfigurerAdapter {

    private UserDetailsService userDetailsService;

    private PowerAuthServiceConfiguration configuration;

    /**
     * Setter for configuration injection.
     * @param configuration Configuration.
     */
    @Autowired
    public void setConfiguration(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Constructor that accepts an instance of UserDetailsService for autowiring.
     * @param userDetailsService UserDetailsService instance.
     */
    @Autowired
    public WebServiceConfig(@Qualifier("integrationUserDetailsService") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Callback handler that uses autowired UserDetailsService to accommodate authentication.
     * @return Password validation callback handler.
     */
    @Bean
    public SpringSecurityPasswordValidationCallbackHandler securityCallbackHandler() {
        SpringSecurityPasswordValidationCallbackHandler callbackHandler = new SpringSecurityPasswordValidationCallbackHandler();
        callbackHandler.setUserDetailsService(userDetailsService);
        return callbackHandler;
    }

    /**
     * Default implementation of WS-Security interceptor that uses "UsernameToken" authentication.
     * @return Default WS-Security interceptor.
     */
    @Bean
    public Wss4jSecurityInterceptor securityInterceptor(){
        Wss4jSecurityInterceptor securityInterceptor = new Wss4jSecurityInterceptor();
        securityInterceptor.setValidationActions("UsernameToken");
        securityInterceptor.setValidationCallbackHandler(securityCallbackHandler());
        return securityInterceptor;
    }

    /**
     * Specify security interceptor in case restricted access is enabled in configuration.
     * @param interceptors Interceptor list, to be enriched with custom interceptor.
     */
    @Override
    public void addInterceptors(List<EndpointInterceptor> interceptors) {
        // If a restricted access is required, add a security interceptor...
        if (configuration.getRestrictAccess()) {
            interceptors.add(securityInterceptor());
        }
        super.addInterceptors(interceptors);
    }

    /**
     * Map the SOAP interface to ${CONTEXT_PATH}/soap path.
     *
     * @param applicationContext Application context.
     * @return New servlet registration with correct context.
     */
    @Bean
    public ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet(ApplicationContext applicationContext) {
        MessageDispatcherServlet servlet = new MessageDispatcherServlet();
        servlet.setApplicationContext(applicationContext);
        servlet.setTransformWsdlLocations(true);
        return new ServletRegistrationBean<>(servlet, "/soap/*");
    }

    /**
     * Specify SOAP service parameters from WSDL file. Map service WSDL to
     * ${CONTEXT_PATH}/soap/serviceV2.wsdl address.
     *
     * @param powerAuthSchema XSD schema with PowerAuth 2.0 service objects.
     * @return PowerAuth 2.0 WSDL definition.
     */
    @Bean(name = "serviceV2")
    public DefaultWsdl11Definition defaultWsdl11DefinitionV2(@Qualifier(value = "powerAuthV2") XsdSchema powerAuthSchema) {
        DefaultWsdl11Definition wsdl11Definition = new DefaultWsdl11Definition();
        wsdl11Definition.setPortTypeName("PowerAuthPortV2");
        wsdl11Definition.setLocationUri("/soap");
        wsdl11Definition.setTargetNamespace("http://getlime.io/security/powerauth/v2");
        wsdl11Definition.setSchema(powerAuthSchema);
        return wsdl11Definition;
    }

    /**
     * Specify SOAP service parameters from WSDL file. Map service WSDL to
     * ${CONTEXT_PATH}/soap/serviceV3.wsdl address.
     *
     * @param powerAuthSchema XSD schema with PowerAuth 3.0 service objects.
     * @return PowerAuth 3.0 WSDL definition.
     */
    @Bean(name = "serviceV3")
    public DefaultWsdl11Definition defaultWsdl11DefinitionV3(@Qualifier(value = "powerAuthV3") XsdSchema powerAuthSchema) {
        DefaultWsdl11Definition wsdl11Definition = new DefaultWsdl11Definition();
        wsdl11Definition.setPortTypeName("PowerAuthPortV3");
        wsdl11Definition.setLocationUri("/soap");
        wsdl11Definition.setTargetNamespace("http://getlime.io/security/powerauth/v3");
        wsdl11Definition.setSchema(powerAuthSchema);
        return wsdl11Definition;
    }

    /**
     * Return PowerAuth 2.0 Server service XSD schema.
     *
     * @return PowerAuth 2.0 XSD schema.
     */
    @Bean(name = "powerAuthV2")
    public XsdSchema powerAuthV2Schema() {
        return new SimpleXsdSchema(new ClassPathResource("xsd/PowerAuth-2.0.xsd"));
    }

    /**
     * Return PowerAuth 3.0 Server service XSD schema.
     *
     * @return PowerAuth 3.0 XSD schema.
     */
    @Bean(name = "powerAuthV3")
    public XsdSchema powerAuthV3Schema() {
        return new SimpleXsdSchema(new ClassPathResource("xsd/PowerAuth-3.0.xsd"));
    }

    /**
     * Exception resolver for SOAP errors.
     * @return SOAP fault resolver.
     */
    @Bean
    public SoapFaultMappingExceptionResolver exceptionResolver() {
        SoapFaultMappingExceptionResolver exceptionResolver = new SoapFaultExceptionResolver();

        SoapFaultDefinition faultDefinition = new SoapFaultDefinition();
        faultDefinition.setFaultCode(SoapFaultDefinition.SERVER);
        exceptionResolver.setDefaultFault(faultDefinition);

        Properties errorMappings = new Properties();
        errorMappings.setProperty(Exception.class.getName(), SoapFaultDefinition.SERVER.toString());
        errorMappings.setProperty(GenericServiceException.class.getName(), SoapFaultDefinition.SERVER.toString());
        errorMappings.setProperty(ActivationRecoveryException.class.getName(), SoapFaultDefinition.SERVER.toString());
        exceptionResolver.setExceptionMappings(errorMappings);
        exceptionResolver.setOrder(1);
        return exceptionResolver;
    }
}
