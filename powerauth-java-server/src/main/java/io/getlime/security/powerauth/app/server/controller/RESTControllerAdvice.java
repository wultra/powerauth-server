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
package io.getlime.security.powerauth.app.server.controller;

import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class used for handling RESTful service errors.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@ControllerAdvice
public class RESTControllerAdvice {

    /**
     * Handle all service exceptions using the same error format. Response has a status code 400 Bad Request.
     *
     * @param e   Service exception.
     * @return REST response with error collection.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = GenericServiceException.class)
    public @ResponseBody RESTResponseWrapper<List<RESTErrorModel>> returnGenericError(GenericServiceException e) {
        RESTErrorModel error = new RESTErrorModel();
        error.setCode(e.getCode());
        error.setMessage(e.getMessage());
        error.setLocalizedMessage(e.getLocalizedMessage());
        List<RESTErrorModel> errorList = new LinkedList<>();
        errorList.add(error);
        Logger.getLogger(RESTControllerAdvice.class.getName()).log(Level.SEVERE, null, e);
        return new RESTResponseWrapper<>("ERROR", errorList);
    }

}
