/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.security.wss4j.Wss4jSecurityInterceptor;
import org.springframework.ws.soap.security.wss4j.callback.SpringSecurityPasswordValidationCallbackHandler;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition;
import org.springframework.xml.xsd.SimpleXsdSchema;
import org.springframework.xml.xsd.XsdSchema;

import java.util.List;

/**
 * PowerAuth 2.0 Server default web service configuration. Configures both basic endpoint information
 * (service, port, xsd) and security (WS-Security, with UsernameToken authentication) in case it is
 * enabled in application configuration ("powerauth.service.restrictAccess").
 *
 * @author Petr Dvorak, petr@lime-company.eu
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
     * Constructor that accepts an instance of UserDetailsServicce for autowiring.
     * @param userDetailsService UserDetailsService instance.
     */
    @Autowired
    public WebServiceConfig(UserDetailsService userDetailsService) {
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
     * Specify SOAP service parameters from WSDL file. Map service WSDP to
     * ${CONTEXT_PATH}/soap/service.wsdl address.
     *
     * @param powerAuthSchema XSD schema with PowerAuth service objects.
     * @return WSDL definition.
     */
    @Bean(name = "service")
    public DefaultWsdl11Definition defaultWsdl11Definition(XsdSchema powerAuthSchema) {
        DefaultWsdl11Definition wsdl11Definition = new DefaultWsdl11Definition();
        wsdl11Definition.setPortTypeName("PowerAuthPort");
        wsdl11Definition.setLocationUri("/soap");
        wsdl11Definition.setTargetNamespace("http://getlime.io/security/powerauth");
        wsdl11Definition.setSchema(powerAuthSchema);
        return wsdl11Definition;
    }

    /**
     * Return PowerAuth 2.0 Server service XSD schema.
     *
     * @return Correct XSD schema.
     */
    @Bean
    public XsdSchema countriesSchema() {
        return new SimpleXsdSchema(new ClassPathResource("xsd/PowerAuth-2.0.xsd"));
    }

}
