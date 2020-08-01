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
import org.springframework.http.HttpStatus;
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

    /**
     * Handle all service exceptions using the same error format. Response has a status code 400 Bad Request.
     *
     * @param ex Service exception.
     * @return REST response with error collection.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = GenericServiceException.class)
    public @ResponseBody ObjectResponse<PowerAuthError> returnGenericError(GenericServiceException ex) {
        PowerAuthError error = new PowerAuthError();
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
        PowerAuthErrorRecovery error = new PowerAuthErrorRecovery();
        error.setCode(ex.getCode());
        error.setMessage(ex.getMessage());
        error.setLocalizedMessage(ex.getLocalizedMessage());
        error.setCurrentRecoveryPukIndex(ex.getCurrentRecoveryPukIndex());
        return new ObjectResponse<>("ERROR", error);
    }

}
