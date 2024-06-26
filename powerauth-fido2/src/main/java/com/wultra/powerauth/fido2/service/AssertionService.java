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

package com.wultra.powerauth.fido2.service;

import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.converter.AssertionChallengeConverter;
import com.wultra.powerauth.fido2.rest.model.converter.AssertionConverter;
import com.wultra.powerauth.fido2.rest.model.converter.AssertionVerificationRequestWrapperConverter;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.Fido2DeserializationException;
import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorData;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import com.wultra.powerauth.fido2.rest.model.request.AssertionVerificationRequestWrapper;
import com.wultra.powerauth.fido2.rest.model.validator.AssertionRequestValidator;
import com.wultra.powerauth.fido2.service.model.Fido2DefaultAuthenticators;
import com.wultra.powerauth.fido2.service.provider.AssertionProvider;
import com.wultra.powerauth.fido2.service.provider.AuthenticatorProvider;
import com.wultra.powerauth.fido2.service.provider.CryptographyService;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorDetail;
import com.wultra.security.powerauth.fido2.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.fido2.model.request.AssertionChallengeRequest;
import com.wultra.security.powerauth.fido2.model.request.AssertionVerificationRequest;
import com.wultra.security.powerauth.fido2.model.response.AssertionChallengeResponse;
import com.wultra.security.powerauth.fido2.model.response.AssertionVerificationResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Base64;

/**
 * Service related to handling assertions.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class AssertionService {

    private final CryptographyService cryptographyService;
    private final AuthenticatorProvider authenticatorProvider;
    private final AssertionProvider assertionProvider;
    private final AssertionConverter assertionConverter;
    private final AssertionRequestValidator assertionRequestValidator;
    private final AssertionVerificationRequestWrapperConverter assertionVerificationRequestWrapperConverter;


    /**
     * Request assertion challenge value.
     *
     * @param request Request with assertion challenge parameters.
     * @return Assertion challenge information.
     */
    public AssertionChallengeResponse requestAssertionChallenge(AssertionChallengeRequest request) throws Exception {

        // Generate the challenge from given request, with optional assignment to provided authenticators
        final AssertionChallenge assertionChallenge = assertionProvider.provideChallengeForAssertion(request);
        if (assertionChallenge == null) {
            throw new Fido2AuthenticationFailedException("Unable to obtain challenge with provided parameters.");
        }

        // Convert the response
        return AssertionChallengeConverter.fromChallenge(assertionChallenge);
    }

    /**
     * Authenticate using the provided request.
     *
     * @param request Request with assertion.
     * @throws Fido2AuthenticationFailedException In case authentication fails.
     */
    public AssertionVerificationResponse authenticate(AssertionVerificationRequest request) throws Fido2AuthenticationFailedException, Fido2DeserializationException {
        final AssertionVerificationRequestWrapper wrapper = assertionVerificationRequestWrapperConverter.convert(request);

        final String error = assertionRequestValidator.validate(wrapper);
        if (error != null) {
            throw new Fido2AuthenticationFailedException(error);
        }

        try {
            final AuthenticatorAssertionResponse response = request.getResponse();
            final String applicationId = request.getApplicationId();
            final CollectedClientData clientDataJSON = wrapper.clientDataJSON();
            final AuthenticatorData authenticatorData = wrapper.authenticatorData();
            final String challenge = clientDataJSON.getChallenge();

            // Obtain clean credential ID encoded in Base64
            String credentialId = request.getCredentialId();
            AuthenticatorDetail authenticatorDetail;
            try {
                logger.debug("Looking up authenticator for credential ID: {}, application ID: {}", credentialId, applicationId);
                authenticatorDetail = getAuthenticatorDetail(credentialId, applicationId);
                logger.info("Found authenticator with ID: {}, for credential ID: {}, application ID: {}", authenticatorDetail.getActivationId(), credentialId, applicationId);
            } catch (Fido2AuthenticationFailedException ex) {
                logger.debug("Authenticator lookup failed, trying find trimmed version.");
                // Try to find trimmed credential ID
                final byte[] credentialIdBytes = Base64.getDecoder().decode(credentialId);
                if (credentialIdBytes.length > 32) {
                   final String credentialIdTrimmed = Base64.getEncoder().encodeToString(Arrays.copyOfRange(credentialIdBytes, 0, 32));
                    logger.debug("Looking up authenticator for trimmed credential ID: {}, application ID: {}", credentialIdTrimmed, applicationId);
                    authenticatorDetail = getAuthenticatorDetail(credentialIdTrimmed, applicationId);
                    // Check if trimming is supported
                    final String aaguid = (String) authenticatorDetail.getExtras().get("aaguid");
                    final boolean isWultraModel = Fido2DefaultAuthenticators.isWultraModel(aaguid);
                    if (isWultraModel) {
                        logger.info("Found authenticator with ID: {}, for trimmed credential ID: {}, application ID: {}, with AAGUID: {}", authenticatorDetail.getActivationId(), credentialIdTrimmed, applicationId, aaguid);
                        credentialId = credentialIdTrimmed;
                    } else {
                        logger.debug("Trimmed credentials are only supported for Wultra models, found trimmed credential ID: {}, application ID: {}, with AAGUID: {}", credentialIdTrimmed, applicationId, aaguid);
                        throw ex;
                    }
                } else {
                    logger.debug("Credential ID: {}, does not have sufficient length (32 bytes) to use trimmed version", credentialId);
                    throw ex;
                }
            }

            if (authenticatorDetail.getActivationStatus() == ActivationStatus.ACTIVE) {
                final boolean signatureCorrect = cryptographyService.verifySignatureForAssertion(applicationId, credentialId, clientDataJSON, authenticatorData, response.getSignature(), authenticatorDetail);
                if (signatureCorrect) {
                    assertionProvider.approveAssertion(challenge, authenticatorDetail, authenticatorData, clientDataJSON);
                    return assertionConverter.fromAuthenticatorDetail(authenticatorDetail, true);
                } else {
                    assertionProvider.failAssertion(challenge, authenticatorDetail, authenticatorData, clientDataJSON);
                    throw new Fido2AuthenticationFailedException("Authentication failed due to incorrect signature.");
                }
            } else {
                assertionProvider.failAssertion(challenge, authenticatorDetail, authenticatorData, clientDataJSON);
                throw new Fido2AuthenticationFailedException("Authentication failed due to incorrect authenticator state.");
            }
        } catch (Exception e) {
            throw new Fido2AuthenticationFailedException("Authentication failed.", e);
        }
    }

    private AuthenticatorDetail getAuthenticatorDetail(String credentialId, String applicationId) throws Fido2AuthenticationFailedException {
        return authenticatorProvider.findByCredentialId(credentialId, applicationId)
                .orElseThrow(() -> new Fido2AuthenticationFailedException("Invalid request"));
    }

}
