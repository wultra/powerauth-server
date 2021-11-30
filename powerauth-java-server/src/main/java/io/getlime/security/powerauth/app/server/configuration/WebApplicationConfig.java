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

import io.getlime.security.powerauth.app.server.controller.RESTResponseExceptionResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.annotation.ResponseStatusExceptionResolver;
import org.springframework.web.servlet.mvc.method.annotation.ExceptionHandlerExceptionResolver;

import java.util.List;

/**
 * PowerAuth Server web application configuration. The main purpose of this class
 * at the moment is to assure proper handling of application exceptions (correct
 * order).
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
public class WebApplicationConfig implements WebMvcConfigurer {

    private final RESTResponseExceptionResolver restResponseExceptionResolver;

    /**
     * Configuration constructor.
     * @param restResponseExceptionResolver REST response exception resolver.
     */
    @Autowired
    public WebApplicationConfig(RESTResponseExceptionResolver restResponseExceptionResolver) {
        this.restResponseExceptionResolver = restResponseExceptionResolver;
    }

    @Override
    public void configureHandlerExceptionResolvers(List<HandlerExceptionResolver> exceptionResolvers) {
        exceptionResolvers.add(restResponseExceptionResolver);
        exceptionResolvers.add(new ExceptionHandlerExceptionResolver());
        exceptionResolvers.add(new ResponseStatusExceptionResolver());
    }

}
