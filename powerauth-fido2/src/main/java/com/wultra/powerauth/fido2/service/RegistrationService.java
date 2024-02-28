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
import com.wultra.powerauth.fido2.rest.model.converter.RegistrationChallengeConverter;
import com.wultra.powerauth.fido2.rest.model.converter.RegistrationConverter;
import com.wultra.powerauth.fido2.rest.model.entity.*;
import com.wultra.powerauth.fido2.rest.model.enumeration.Fmt;
import com.wultra.powerauth.fido2.rest.model.request.RegistrationRequest;
import com.wultra.powerauth.fido2.rest.model.response.RegisteredAuthenticatorsResponse;
import com.wultra.powerauth.fido2.rest.model.response.RegistrationChallengeResponse;
import com.wultra.powerauth.fido2.rest.model.response.RegistrationResponse;
import com.wultra.powerauth.fido2.rest.model.validator.RegistrationRequestValidator;
import com.wultra.powerauth.fido2.service.provider.AuthenticatorProvider;
import com.wultra.powerauth.fido2.service.provider.CryptographyService;
import com.wultra.powerauth.fido2.service.provider.RegistrationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service related to handling registrations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class RegistrationService {

    private final AuthenticatorProvider authenticatorProvider;
    private final RegistrationProvider registrationProvider;
    private final RegistrationChallengeConverter registrationChallengeConverter;
    private final RegistrationConverter registrationConverter;
    private final RegistrationRequestValidator registrationRequestValidator;
    private final CryptographyService cryptographyService;

    /**
     * Registration service.
     *
     * @param authenticatorProvider Authenticator provider.
     * @param registrationProvider Registration provider.
     * @param registrationChallengeConverter Registration challenge converter.
     * @param registrationConverter Registration converter.
     * @param registrationRequestValidator Registration request validator.
     * @param cryptographyService Cryptography service.
     */
    @Autowired
    public RegistrationService(AuthenticatorProvider authenticatorProvider, RegistrationProvider registrationProvider, RegistrationChallengeConverter registrationChallengeConverter, RegistrationConverter registrationConverter, RegistrationRequestValidator registrationRequestValidator, CryptographyService cryptographyService) {
        this.authenticatorProvider = authenticatorProvider;
        this.registrationProvider = registrationProvider;
        this.registrationChallengeConverter = registrationChallengeConverter;
        this.registrationConverter = registrationConverter;
        this.registrationRequestValidator = registrationRequestValidator;
        this.cryptographyService = cryptographyService;
    }

    /**
     * List registrations for a user.
     *
     * @param userId User identifier.
     * @param applicationId Application identifier.
     * @return Registered authenticator list response.
     * @throws Fido2AuthenticationFailedException In case list request fails.
     */
    public RegisteredAuthenticatorsResponse listRegistrationsForUser(String userId, String applicationId) throws Fido2AuthenticationFailedException {
        final RegisteredAuthenticatorsResponse responseObject = new RegisteredAuthenticatorsResponse();
        responseObject.getAuthenticators().addAll(authenticatorProvider.findByUserId(userId, applicationId));
        return responseObject;
    }

    /**
     * Request a registration challenge.
     *
     * @param userId User identifier.
     * @param applicationId Application identifier.
     * @return Registration challenge response.
     * @throws Exception Thrown in case creating challenge fails.
     */
    public RegistrationChallengeResponse requestRegistrationChallenge(String userId, String applicationId) throws Exception {
        final RegistrationChallenge challenge = registrationProvider.provideChallengeForRegistration(userId, applicationId);
        return registrationChallengeConverter.fromChallenge(challenge);
    }

    /**
     * Register an authenticator.
     *
     * @param requestObject Registration request.
     * @return Registration response.
     * @throws Exception Thrown in case registration fails.
     */
    public RegistrationResponse register(RegistrationRequest requestObject) throws Exception {
        final String applicationId = requestObject.getApplicationId();

        final String error = registrationRequestValidator.validate(requestObject);
        if (error != null) {
            throw new Fido2AuthenticationFailedException(error);
        }

        final String authenticatorId = requestObject.getAuthenticatorParameters().getId();
        final AuthenticatorAttestationResponse response = requestObject.getAuthenticatorParameters().getResponse();

        final CollectedClientData clientDataJSON = response.getClientDataJSON();
        final String challengeValue = clientDataJSON.getChallenge();

        final AttestationObject attestationObject = response.getAttestationObject();
        final AttestationStatement attStmt = attestationObject.getAttStmt();
        final byte[] signature = attStmt.getSignature();

        final AuthenticatorData authData = attestationObject.getAuthData();
        final AttestedCredentialData attestedCredentialData = authData.getAttestedCredentialData();

        final String fmt = attestationObject.getFmt();
        final byte[] aaguid = attestationObject.getAuthData().getAttestedCredentialData().getAaguid();

        validateRegistrationRequest(applicationId, authenticatorId, fmt, aaguid, challengeValue);

        if (Fmt.FMT_PACKED.getValue().equals(fmt)) {
            final boolean verifySignature = cryptographyService.verifySignatureForRegistration(applicationId, clientDataJSON, authData, signature, attestedCredentialData);
            if (!verifySignature) {
                // Immediately revoke the challenge
                registrationProvider.revokeRegistrationByChallengeValue(applicationId, challengeValue);
                throw new Fido2AuthenticationFailedException("Registration failed");
            }
            logger.info("Signature verification on registration performed using packed attestation format");
        } else {
            logger.info("No signature verification on registration");
        }

        final RegistrationChallenge challenge = registrationProvider.findRegistrationChallengeByValue(applicationId, challengeValue);
        final Optional<AuthenticatorDetail> authenticatorOptional = registrationConverter.convert(challenge, requestObject, attestedCredentialData.getAaguid(), cryptographyService.publicKeyToBytes(attestedCredentialData.getPublicKeyObject()));
        authenticatorOptional.orElseThrow(() -> new Fido2AuthenticationFailedException("Invalid request"));
        final AuthenticatorDetail authenticatorDetailResponse = authenticatorProvider.storeAuthenticator(requestObject.getApplicationId(), challenge.getChallenge(), authenticatorOptional.get());
        return registrationConverter.convertRegistrationResponse(authenticatorDetailResponse);
    }

    private void validateRegistrationRequest(final String applicationId, final String authenticatorId, final String attestationFormat, final byte[] aaguid, final String challengeValue) throws Exception {
        if (!registrationProvider.registrationAllowed(applicationId, authenticatorId, attestationFormat, aaguid)) {
            logger.warn("Invalid request for FIDO2 registration");
            // Immediately revoke the challenge
            registrationProvider.revokeRegistrationByChallengeValue(applicationId, challengeValue);
            throw new Fido2AuthenticationFailedException("Registration failed");
        }
    }

}
