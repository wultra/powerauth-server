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

import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import com.wultra.security.powerauth.client.model.error.PowerAuthErrorRecovery;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.exceptions.ActivationRecoveryException;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.exceptions.TelemetryReportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Class used for handling RESTful service errors.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@ControllerAdvice
public class RESTControllerAdvice {

    private static final Logger logger = LoggerFactory.getLogger(RESTControllerAdvice.class);

    /**
     * Resolver for Activation Recovery Exception.
     * @param ex Activation Recovery Exception.
     * @return Activation recovery error.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = TelemetryReportException.class)
    public @ResponseBody ObjectResponse<PowerAuthError> handleUnknownTelemetryReportNameException(TelemetryReportException ex) {
        logger.error("Error occurred while processing the request: {}", ex.getMessage());
        logger.debug("Exception details:", ex);
        final PowerAuthError error = new PowerAuthError();
        error.setCode("ERROR_TELEMETRY");
        error.setMessage(ex.getMessage());
        error.setLocalizedMessage(ex.getLocalizedMessage());
        return new ObjectResponse<>("ERROR", error);
    }

    /**
     * Handle all service exceptions using the same error format. Response has a status code 400 Bad Request.
     *
     * @param ex Service exception.
     * @return REST response with error collection.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = GenericServiceException.class)
    public @ResponseBody ObjectResponse<PowerAuthError> returnGenericError(GenericServiceException ex) {
        logger.error("Error occurred while processing the request: {}", ex.getMessage());
        logger.debug("Exception details:", ex);
        final PowerAuthError error = new PowerAuthError();
        error.setCode(ex.getCode());
        error.setMessage(ex.getMessage());
        error.setLocalizedMessage(ex.getLocalizedMessage());
        return new ObjectResponse<>("ERROR", error);
    }

    /**
     * Resolver for Activation Recovery Exception.
     * @param ex Activation Recovery Exception.
     * @return Activation recovery error.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = ActivationRecoveryException.class)
    public @ResponseBody ObjectResponse<PowerAuthError> returnActivationRecoveryError(ActivationRecoveryException ex) {
        logger.error("Error occurred while processing the request: {}", ex.getMessage());
        logger.debug("Exception details:", ex);
        final PowerAuthErrorRecovery error = new PowerAuthErrorRecovery();
        error.setCode("ERR_RECOVERY");
        error.setMessage(ex.getMessage());
        error.setLocalizedMessage(ex.getLocalizedMessage());
        error.setCurrentRecoveryPukIndex(ex.getCurrentRecoveryPukIndex());
        return new ObjectResponse<>("ERROR", error);
    }

    /**
     * Resolver for HTTP request message errors.
     * @param ex Exception for HTTP message not readable.
     * @return Error for HTTP request.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = HttpMessageNotReadableException.class)
    public @ResponseBody ObjectResponse<PowerAuthError> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        logger.error("Error occurred while processing the request: {}", ex.getMessage());
        logger.debug("Exception details:", ex);
        final PowerAuthErrorRecovery error = new PowerAuthErrorRecovery();
        error.setCode("ERROR_HTTP_REQUEST");
        error.setMessage(ex.getMessage());
        error.setLocalizedMessage(ex.getLocalizedMessage());
        return new ObjectResponse<>("ERROR", error);
    }

}
