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
import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorAssertionResponse;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
import com.wultra.powerauth.fido2.rest.model.request.AssertionChallengeRequest;
import com.wultra.powerauth.fido2.rest.model.request.AssertionRequest;
import com.wultra.powerauth.fido2.rest.model.response.AssertionChallengeResponse;
import com.wultra.powerauth.fido2.rest.model.response.AssertionVerificationResponse;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service related to handling assertions.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class AssertionService {

    private final CryptographyService cryptographyService;
    private final ChallengeProvider challengeProvider;
    private final AuthenticatorProvider authenticatorProvider;
    private final AssertionConverter assertionConverter;
    private final AssertionChallengeConverter assertionChallengeConverter;

    @Autowired
    public AssertionService(CryptographyService cryptographyService, ChallengeProvider challengeProvider, AuthenticatorProvider authenticatorProvider, AssertionConverter assertionConverter, AssertionChallengeConverter assertionChallengeConverter) {
        this.cryptographyService = cryptographyService;
        this.challengeProvider = challengeProvider;
        this.authenticatorProvider = authenticatorProvider;
        this.assertionConverter = assertionConverter;
        this.assertionChallengeConverter = assertionChallengeConverter;
    }

    /**
     * Request assertion challenge value.
     *
     * @param request Request with assertion challenge parameters.
     * @return Assertion challenge information.
     */
    public AssertionChallengeResponse requestAssertionChallenge(AssertionChallengeRequest request) throws Exception {
        final AssertionChallenge assertionChallenge = challengeProvider.provideChallengeForAuthentication(
                null, request.getApplicationIds(), request.getOperationType(), request.getParameters(), request.getExternalId()
        );
        if (assertionChallenge == null) {
            throw new Fido2AuthenticationFailedException("Unable to obtain challenge with provided parameters.");
        }
        return assertionChallengeConverter.fromChallenge(assertionChallenge);
    }

    /**
     * Authenticate using the provided request.
     *
     * @param request Request with assertion.
     * @throws Fido2AuthenticationFailedException In case authentication fails.
     */
    public AssertionVerificationResponse authenticate(AssertionRequest request) throws Fido2AuthenticationFailedException {
        try {
            final AuthenticatorAssertionResponse response = request.getResponse();
            final String applicationId = request.getApplicationId();
            final String authenticatorId = request.getId();
            final AuthenticatorDetail authenticatorDetail = authenticatorProvider.findByCredentialId(applicationId, authenticatorId);
            if (authenticatorDetail.getActivationStatus() == ActivationStatus.ACTIVE) {
                final boolean signatureCorrect = cryptographyService.verifySignatureForAssertion(applicationId, authenticatorId, response.getClientDataJSON(), response.getAuthenticatorData(), response.getSignature(), authenticatorDetail);
                if (signatureCorrect) {
                    return assertionConverter.fromAuthenticatorDetail(authenticatorDetail, signatureCorrect);
                } else {
                    throw new Fido2AuthenticationFailedException("Authentication failed due to incorrect signature.");
                }
            } else {
                throw new Fido2AuthenticationFailedException("Authentication failed due to incorrect authenticator state.");
            }
        } catch (Exception e) {
            throw new Fido2AuthenticationFailedException("Authentication failed.", e);
        }
    }

}
