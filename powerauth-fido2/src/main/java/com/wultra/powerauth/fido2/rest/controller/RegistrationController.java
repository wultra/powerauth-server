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

import com.wultra.powerauth.fido2.service.RegistrationService;
import com.wultra.security.powerauth.fido2.model.request.RegisteredAuthenticatorsRequest;
import com.wultra.security.powerauth.fido2.model.request.RegistrationChallengeRequest;
import com.wultra.security.powerauth.fido2.model.request.RegistrationRequest;
import com.wultra.security.powerauth.fido2.model.response.RegisteredAuthenticatorsResponse;
import com.wultra.security.powerauth.fido2.model.response.RegistrationChallengeResponse;
import com.wultra.security.powerauth.fido2.model.response.RegistrationResponse;
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
@Tag(name = "FIDO2 Registrations Controller", description = "API for FIDO2 authenticator registrations")
public class RegistrationController {

    private final RegistrationService registrationService;

    /**
     * Registration controller constructor.
     * @param registrationService Registration service.
     */
    @Autowired
    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    /**
     * Obtain a list of registered FIDO2 authenticators.
     * @param request Registered authenticators list request.
     * @return Registered authenticators list response.
     * @throws Exception Thrown in case registered authenticators list could not be obtained.
     */
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
        logger.info("RegisteredAuthenticatorsRequest received: {}", request);
        final ObjectResponse<RegisteredAuthenticatorsResponse> response = new ObjectResponse<>(registrationService.listRegistrationsForUser(request.getRequestObject()));
        logger.info("RegisteredAuthenticatorsRequest succeeded: {}", response);
        return response;
    }

    /**
     * Request a registration challenge.
     * @param request Registration challenge request.
     * @return Registration challenge response.
     * @throws Exception Thrown in case registration challenge could not be generated.
     */
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
        logger.info("RegistrationChallengeRequest received: {}", request);
        final ObjectResponse<RegistrationChallengeResponse> response = new ObjectResponse<>(registrationService.requestRegistrationChallenge(request.getRequestObject()));
        logger.info("RegistrationChallengeRequest succeeded: {}", response);
        return response;
    }

    /**
     * Register an authenticator.
     * @param request Register an authenticator request.
     * @return Register an authenticator response.
     * @throws Exception Thrown in case registration fails.
     */
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
        logger.info("RegistrationRequest received: {}", request);
        final ObjectResponse<RegistrationResponse> response = new ObjectResponse<>(registrationService.register(request.getRequestObject()));
        logger.info("RegistrationRequest succeeded: {}", response);
        return response;
    }

}
