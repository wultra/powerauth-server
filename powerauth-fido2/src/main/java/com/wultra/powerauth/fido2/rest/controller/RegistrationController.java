/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package com.wultra.powerauth.fido2.rest.controller;

import com.wultra.powerauth.fido2.rest.model.request.RegisteredAuthenticatorsRequest;
import com.wultra.powerauth.fido2.rest.model.request.RegistrationChallengeRequest;
import com.wultra.powerauth.fido2.rest.model.request.RegistrationRequest;
import com.wultra.powerauth.fido2.rest.model.response.RegisteredAuthenticatorsResponse;
import com.wultra.powerauth.fido2.rest.model.response.RegistrationChallengeResponse;
import com.wultra.powerauth.fido2.rest.model.response.RegistrationResponse;
import com.wultra.powerauth.fido2.service.RegistrationService;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller responsible for FIDO2 authenticator registration handling.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Validated
@RestController
@RequestMapping("fido2/registrations")
@Slf4j
@Tag(name = "FIDO2 Registration Controller", description = "API for FIDO2 authenticator registrations")
public class RegistrationController {

    private final RegistrationService registrationService;

    @Autowired
    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @Operation(
            summary = "List registered authenticators",
            description = "Obtain a list of registered FIDO2 authenticators for specified user."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of registered authenticators received"),
            @ApiResponse(responseCode = "400", description = "Invalid request"),
            @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PostMapping("list")
    public ObjectResponse<RegisteredAuthenticatorsResponse> registeredAuthenticators(@Valid @RequestBody ObjectRequest<RegisteredAuthenticatorsRequest> request) throws Exception {
        final RegisteredAuthenticatorsRequest requestObject = request.getRequestObject();
        final RegisteredAuthenticatorsResponse responseObject = registrationService.registrationsForUser(requestObject.getUserId(), requestObject.getApplicationId());
        return new ObjectResponse<>(responseObject);
    }

    @Operation(
            summary = "Generate a registration challenge",
            description = "Generate a FIDO2 registration challenge for specified user."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Registration challenge was generated"),
            @ApiResponse(responseCode = "400", description = "Invalid request"),
            @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PostMapping("challenge")
    public ObjectResponse<RegistrationChallengeResponse> requestRegistrationChallenge(@Valid @RequestBody ObjectRequest<RegistrationChallengeRequest> request) throws Exception {
        final RegistrationChallengeRequest requestObject = request.getRequestObject();
        final RegistrationChallengeResponse responseObject = registrationService.requestRegistrationChallenge(requestObject.getUserId(), requestObject.getApplicationId());
        return new ObjectResponse<>(responseObject);
    }

    @Operation(
            summary = "Register an authenticator",
            description = "Register a FIDO2 authenticator based on a registration request generated and signed by the authenticator."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Registration succeeded"),
            @ApiResponse(responseCode = "400", description = "Invalid request or request signature verification failed"),
            @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PostMapping
    public ObjectResponse<RegistrationResponse> register(@Valid @RequestBody ObjectRequest<RegistrationRequest> request) throws Exception {
        final RegistrationRequest requestObject = request.getRequestObject();
        final RegistrationResponse responseObject = registrationService.register(requestObject);
        return new ObjectResponse<>(responseObject);
    }

}