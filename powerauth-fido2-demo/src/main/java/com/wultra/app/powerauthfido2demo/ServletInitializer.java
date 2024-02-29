package com.wultra.app.powerauthfido2demo;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * Spring Boot servlet initializer
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
public class ServletInitializer extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(PowerauthFido2DemoApplication.class);
    }

}
