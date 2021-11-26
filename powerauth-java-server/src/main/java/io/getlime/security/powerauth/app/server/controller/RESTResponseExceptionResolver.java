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
package io.getlime.security.powerauth.app.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import com.wultra.security.powerauth.client.model.error.PowerAuthErrorRecovery;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.exceptions.ActivationRecoveryException;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Exception resolver responsible for catching Spring errors and rendering them in
 * the same format as the application logic exceptions.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class RESTResponseExceptionResolver extends DefaultHandlerExceptionResolver {

    private static final Logger logger = LoggerFactory.getLogger(RESTResponseExceptionResolver.class);

    private final ObjectMapper objectMapper;

    /**
     * Default constructor.
     * @param objectMapper Object mapper.
     */
    public RESTResponseExceptionResolver(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        super.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
    }

    @Override
    @Nullable
    protected ModelAndView doResolveException(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @Nullable Object handler, @NonNull Exception exception) {
        try {

            // Log the exception
            logger.warn("An exception occurred in Spring Framework while processing the request", exception);

            // Build the error
            PowerAuthError error;
            if (exception instanceof ActivationRecoveryException) {
                PowerAuthErrorRecovery errorRecovery = new PowerAuthErrorRecovery();
                errorRecovery.setCode("ERR_RECOVERY");
                errorRecovery.setMessage(exception.getMessage());
                errorRecovery.setLocalizedMessage(exception.getLocalizedMessage());
                errorRecovery.setCurrentRecoveryPukIndex(((ActivationRecoveryException) exception).getCurrentRecoveryPukIndex());
                error = errorRecovery;
            } else if (exception instanceof GenericServiceException) {
                GenericServiceException ex = (GenericServiceException) exception;
                error = new PowerAuthError();
                error.setCode(ex.getCode());
                error.setMessage(ex.getMessage());
                error.setLocalizedMessage(ex.getLocalizedMessage());
            } else {
                error = new PowerAuthError();
                error.setCode("ERR_SPRING_JAVA");
                error.setMessage(exception.getMessage());
                error.setLocalizedMessage(exception.getLocalizedMessage());
            }

            // Prepare the response
            ObjectResponse<PowerAuthError> errorResponse = new ObjectResponse<>("ERROR", error);

            // Write the response in JSON and send it
            String responseString = objectMapper.writeValueAsString(errorResponse);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getOutputStream().print(responseString);
            response.flushBuffer();
        } catch (IOException e) {
            // Response object does have an output stream here
            logger.error("An exception occurred while serializing JSON error response", e);
        }
        return new ModelAndView();
    }

}
