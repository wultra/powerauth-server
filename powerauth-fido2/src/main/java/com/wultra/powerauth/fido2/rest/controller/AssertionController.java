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

import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.request.AssertionChallengeRequest;
import com.wultra.powerauth.fido2.rest.model.request.AssertionVerificationRequest;
import com.wultra.powerauth.fido2.rest.model.response.AssertionChallengeResponse;
import com.wultra.powerauth.fido2.rest.model.response.AssertionVerificationResponse;
import com.wultra.powerauth.fido2.rest.model.validator.AssertionRequestValidator;
import com.wultra.powerauth.fido2.service.AssertionService;
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
 * Controller responsible for FIDO2 assertion handling.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Validated
@RestController
@RequestMapping("fido2/assertions")
@Slf4j
@Tag(name = "FIDO2 Assertions Controller", description = "API for FIDO2 assertions")
public class AssertionController {

    private final AssertionRequestValidator assertionRequestValidator;
    private final AssertionService assertionService;

    /**
     * Assertion controller constructor.
     * @param assertionRequestValidator Assertion request validator.
     * @param assertionService Assertion service.
     */
    @Autowired
    public AssertionController(AssertionRequestValidator assertionRequestValidator, AssertionService assertionService) {
        this.assertionRequestValidator = assertionRequestValidator;
        this.assertionService = assertionService;
    }

    /**
     * Request generating of an assertion challenge for an operation.
     * @param request Assertion challenge request.
     * @return Assertion challenge response.
     * @throws Exception Thrown in case assertion challenge could not be generated.
     */
    @Operation(
            summary = "Generate an assertion challenge",
            description = "Generate a FIDO2 assertion challenge for an operation."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Assertion challenge was generated"),
            @ApiResponse(responseCode = "400", description = "Invalid request"),
            @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PostMapping("challenge")
    public ObjectResponse<AssertionChallengeResponse> requestAssertionChallenge(@Valid @RequestBody ObjectRequest<AssertionChallengeRequest> request) throws Exception {
        final AssertionChallengeRequest requestObject = request.getRequestObject();
        logger.info("AssertionChallengeRequest received, application IDs: {}", requestObject.getApplicationIds());
        final AssertionChallengeResponse assertionChallengeResponse = assertionService.requestAssertionChallenge(requestObject);
        logger.info("AssertionChallengeRequest succeeded, application IDs: {}", requestObject.getApplicationIds());
        return new ObjectResponse<>(assertionChallengeResponse);
    }

    /**
     * Verify a FIDO2 assertion for an operation.
     * @param request Verify an assertion request.
     * @return Verify an assertion response.
     * @throws Fido2AuthenticationFailedException Thrown in case assertion validation fails.
     */
    @Operation(
            summary = "Verify an assertion",
            description = "Verify a FIDO2 assertion for an operation based on an assertion verification request generated and signed by the authenticator."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Assertion verification succeeded"),
            @ApiResponse(responseCode = "400", description = "Invalid request or assertion verification failed"),
            @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PostMapping
    public ObjectResponse<AssertionVerificationResponse> authenticate(@Valid @RequestBody ObjectRequest<AssertionVerificationRequest> request) throws Fido2AuthenticationFailedException {
        final AssertionVerificationRequest requestObject = request.getRequestObject();
        logger.info("AssertionVerificationRequest received, credential ID: {}", requestObject.getCredentialId());
        final String error = assertionRequestValidator.validate(requestObject);
        if (error != null) {
            throw new Fido2AuthenticationFailedException(error);
        }
        final AssertionVerificationResponse signatureResponse = assertionService.authenticate(requestObject);
        logger.info("AssertionVerificationRequest succeeded, credential ID: {}, valid: {}", requestObject.getCredentialId(), signatureResponse.isAssertionValid());
        return new ObjectResponse<>(signatureResponse);
    }

}
