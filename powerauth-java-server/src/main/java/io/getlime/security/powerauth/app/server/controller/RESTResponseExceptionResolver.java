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
import io.getlime.security.powerauth.app.server.service.exceptions.ActivationRecoveryException;
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
import java.util.LinkedList;
import java.util.List;

/**
 * Exception resolver responsible for catching Spring errors and rendering them in
 * the same format as the application logics exceptions.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class RESTResponseExceptionResolver extends DefaultHandlerExceptionResolver {

    /**
     * Default constructor.
     */
    public RESTResponseExceptionResolver() {
        super.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
    }

    @Override
    @Nullable
    protected ModelAndView doResolveException(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @Nullable Object handler, @NonNull Exception exception) {
        try {
            // Build the error list
            List<RESTErrorModel> errorList = new LinkedList<>();
            if (exception instanceof ActivationRecoveryException) {
                RESTErrorModelRecovery recoveryError = new RESTErrorModelRecovery();
                recoveryError.setCode("ERR_RECOVERY");
                recoveryError.setMessage(exception.getMessage());
                recoveryError.setLocalizedMessage(exception.getLocalizedMessage());
                recoveryError.setCurrentRecoveryPukIndex(((ActivationRecoveryException) exception).getCurrentRecoveryPukIndex());
                errorList.add(recoveryError);
            } else {
                RESTErrorModel error = new RESTErrorModel();
                error.setCode("ERR_SPRING_JAVA");
                error.setMessage(exception.getMessage());
                error.setLocalizedMessage(exception.getLocalizedMessage());
                errorList.add(error);
            }

            // Prepare the response
            RESTResponseWrapper<List<RESTErrorModel>> errorResponse = new RESTResponseWrapper<>("ERROR", errorList);

            // Write the response in JSON and send it
            ObjectMapper mapper = new ObjectMapper();
            String responseString = mapper.writeValueAsString(errorResponse);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getOutputStream().print(responseString);
            response.flushBuffer();
        } catch (IOException e) {
            // Response object does have an output stream here
        }
        return new ModelAndView();
    }

}
