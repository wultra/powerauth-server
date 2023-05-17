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

import com.wultra.powerauth.fido2.rest.model.entity.*;
import com.wultra.powerauth.fido2.rest.model.enumeration.Fmt;
import com.wultra.powerauth.fido2.rest.model.enumeration.SignatureAlgorithm;
import com.wultra.powerauth.fido2.rest.model.request.RegistrationRequest;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * Validator for registration request.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class RegistrationRequestValidator {

    public String validate(RegistrationRequest request) {

        if (request == null || request.getResponse() == null
                || request.getResponse().getClientDataJSON() == null
                || request.getResponse().getAttestationObject() == null) {
            return "Invalid request, you need to include response.clientDataJSON and response.attestationObject.";
        }

        final CollectedClientData clientDataJSON = request.getResponse().getClientDataJSON();

        if (!"webauthn.create".equals(clientDataJSON.getType())) {
            return "Request does not contain webauthn.create type.";
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

        final AttestationObject attestationObject = request.getResponse().getAttestationObject();
        final AuthenticatorData authData = attestationObject.getAuthData();
        if (authData == null) {
            return "Missing authentication data.";
        }

        final byte[] rpIdHash = authData.getRpIdHash();
        final String relyingPartyId = request.getRelyingPartyId();
        final byte[] expectedRpIdHash = Hash.sha256(relyingPartyId);
        if (!Arrays.equals(rpIdHash, expectedRpIdHash)) {
            return "The origin does not match relying party ID.";
        }

        final Flags flags = authData.getFlags();

        if (!flags.isUserPresent()) {
            return "User is not present during the authentication.";
        }

        final boolean requiresUserVerification = request.isRequiresUserVerification();
        if (requiresUserVerification && !flags.isUserVerified()) {
            return "User is not present during the authentication, but user verification is required.";
        }

        final String fmt = attestationObject.getFmt();
        if (!Fmt.allowedFmt.contains(fmt)) {
            return "Invalid attestation format identifier.";
        }

        final AttestedCredentialData attestedCredentialData = authData.getAttestedCredentialData();
        if (attestedCredentialData == null) {
            return "Missing attestation data.";
        }

        final PublicKeyObject publicKeyObject = attestedCredentialData.getPublicKeyObject();
        if (publicKeyObject == null) {
            return "Missing public key inside attestation data";
        }

        final SignatureAlgorithm algorithm = publicKeyObject.getAlgorithm();
        if (SignatureAlgorithm.ES256 != algorithm) {
            return "The provided algorithm is not supported by the server.";
        }

        if (fmt.equals(Fmt.FMT_PACKED.getValue())) {
            final AttestationStatement attStmt = attestationObject.getAttStmt();
            if (!attStmt.getAlgorithm().equals(algorithm)) {
                return "Attestation algorithm does not match algorithm used for the public key.";
            }
        }

        return null;
    }

}
