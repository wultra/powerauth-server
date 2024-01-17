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

package com.wultra.powerauth.fido2.rest.model.validator;

import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorData;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import com.wultra.powerauth.fido2.rest.model.request.AssertionVerificationRequest;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * Validator for the assertion request class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class AssertionRequestValidator {

    public String validate(AssertionVerificationRequest request) {

        if (request == null || request.getResponse() == null
                || request.getResponse().getClientDataJSON() == null
                || request.getResponse().getAuthenticatorData() == null) {
            return "Invalid request, you need to include response.clientDataJSON and response.attestationObject.";
        }

        final CollectedClientData clientDataJSON = request.getResponse().getClientDataJSON();

        if (clientDataJSON == null) {
            return "Request deserialization failed.";
        }

        if (!"webauthn.get".equals(clientDataJSON.getType())) {
            return "Request does not contain webauthn.get type.";
        }

        final String expectedChallenge = request.getExpectedChallenge();
        if (expectedChallenge != null && !expectedChallenge.equals(clientDataJSON.getChallenge())) {
            return "Request does not contain the correct challenge.";
        }

        final String origin = clientDataJSON.getOrigin();
        final List<String> allowedOrigins = request.getAllowedOrigins();
        if (origin == null || !allowedOrigins.contains(origin)) {
            return "Request does not contain the correct origin.";
        }

        final List<String> allowedTopOrigins = request.getAllowedTopOrigins();
        if (clientDataJSON.getTopOrigin() != null && !allowedTopOrigins.contains(clientDataJSON.getTopOrigin())) {
            return "Request contains the top origin which is not allowed.";
        }

        final AuthenticatorData authenticatorData = request.getResponse().getAuthenticatorData();

        final byte[] rpIdHash = authenticatorData.getRpIdHash();
        final String relyingPartyId = request.getRelyingPartyId();
        final byte[] expectedRpIdHash = Hash.sha256(relyingPartyId);
        if (!Arrays.equals(rpIdHash, expectedRpIdHash)) {
            return "The origin does not match relying party ID.";
        }

        if (!authenticatorData.getFlags().isUserPresent()) {
            return "User is not present during the authentication.";
        }

        final boolean requiresUserVerification = request.isRequiresUserVerification();
        if (requiresUserVerification && !authenticatorData.getFlags().isUserVerified()) {
            return "User is not present during the authentication, but user verification is required.";
        }

        return null;
    }

}
