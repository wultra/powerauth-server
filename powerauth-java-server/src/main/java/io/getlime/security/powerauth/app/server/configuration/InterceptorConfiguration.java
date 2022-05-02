/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.interceptor.HttpHeaderInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuration of interceptors.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@ConditionalOnProperty(
        value = "powerauth.service.correlation-header.enabled",
        havingValue = "true"
)
public class InterceptorConfiguration implements WebMvcConfigurer {

    @Value("${powerauth.service.correlation-header.name:X-Correlation-ID}")
    private String correlationHeaderName;

    @Value("${powerauth.service.correlation-header.value.validation-regexp:[a-zA-Z0-9\\-]{8,128}}")
    private String correlationHeaderValueValidation;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        HandlerInterceptor httpHeaderInterceptor = new HttpHeaderInterceptor(correlationHeaderName, correlationHeaderValueValidation);
        registry.addInterceptor(httpHeaderInterceptor);
    }
}