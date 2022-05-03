/*
 * PowerAuth Server and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.interceptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * HTTP header interceptor for logging of correlation headers using MDC.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class HttpHeaderInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(HttpHeaderInterceptor.class);

    private final String correlationHeaderName;
    private final String correlationHeaderValueValidation;

    public HttpHeaderInterceptor(String correlationHeaderName, String correlationHeaderValueValidation) {
        this.correlationHeaderName = correlationHeaderName;
        this.correlationHeaderValueValidation = correlationHeaderValueValidation;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        MDC.put(correlationHeaderName, getCorrelationId(request));
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        MDC.remove(correlationHeaderName);
    }

    private String getCorrelationId(HttpServletRequest request) {
        final String headerValue = request.getHeader(correlationHeaderName);
        if (headerValue == null) {
            logger.debug("Correlation header {} is null", correlationHeaderName);
            return null;
        }
        if (!headerValue.matches(correlationHeaderValueValidation)) {
            logger.warn("Correlation header {} is invalid: {}", correlationHeaderName, headerValue);
            return null;
        }
        return headerValue;
    }
}