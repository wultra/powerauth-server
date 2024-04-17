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
import com.wultra.powerauth.fido2.rest.model.enumeration.CurveType;
import com.wultra.powerauth.fido2.rest.model.enumeration.ECKeyType;
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

    /**
     * Validate a registration request.
     * @param request Registration request.
     * @return Validation result.
     */
    public String validate(RegistrationRequest request) {

        if (request == null) {
            return "Null request provided.";
        }

        final AuthenticatorParameters authenticatorParameters = request.getAuthenticatorParameters();

        if (authenticatorParameters == null) {
            return "Null authenticator parameters provided.";
        }

        final AuthenticatorAttestationResponse response = authenticatorParameters.getResponse();

        if (response == null
                || response.getClientDataJSON() == null
                || response.getAttestationObject() == null) {
            return "Invalid request authenticator parameters, you need to include response.clientDataJSON and response.attestationObject.";
        }

        final CollectedClientData clientDataJSON = response.getClientDataJSON();

        if (!"webauthn.create".equals(clientDataJSON.getType())) {
            return "Request does not contain webauthn.create type.";
        }

        final String expectedChallenge = request.getExpectedChallenge();
        if (expectedChallenge != null && !expectedChallenge.equals(clientDataJSON.getChallenge())) {
            return "Request does not contain the correct challenge.";
        }

        final String origin = clientDataJSON.getOrigin();
        final List<String> allowedOrigins = authenticatorParameters.getAllowedOrigins();
        if (origin == null || !allowedOrigins.contains(origin)) {
            return "Request does not contain the correct origin.";
        }

        final List<String> allowedTopOrigins = authenticatorParameters.getAllowedTopOrigins();
        if (clientDataJSON.getTopOrigin() != null && !allowedTopOrigins.contains(clientDataJSON.getTopOrigin())) {
            return "Request contains the top origin which is not allowed.";
        }

        final AttestationObject attestationObject = response.getAttestationObject();
        final AuthenticatorData authData = attestationObject.getAuthData();
        if (authData == null) {
            return "Missing authentication data.";
        }

        final byte[] rpIdHash = authData.getRpIdHash();
        final String relyingPartyId = authenticatorParameters.getRelyingPartyId();
        final byte[] expectedRpIdHash = Hash.sha256(relyingPartyId);
        if (!Arrays.equals(rpIdHash, expectedRpIdHash)) {
            return "The relying party ID stored with authenticator does not match the relying party ID provided in the request.";
        }

        final Flags flags = authData.getFlags();

        if (!flags.isUserPresent()) {
            return "User is not present during the authentication.";
        }

        final boolean requiresUserVerification = authenticatorParameters.isRequiresUserVerification();
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

        final byte[] credentialId = attestedCredentialData.getCredentialId();
        if (credentialId == null) {
            return "Missing credential identifier.";
        }

        final byte[] aaguid = attestedCredentialData.getAaguid();
        if (aaguid == null) {
            return "Missing aaguid.";
        }

        final PublicKeyObject publicKeyObject = attestedCredentialData.getPublicKeyObject();
        if (publicKeyObject == null) {
            return "Missing public key inside attestation data";
        }

        final SignatureAlgorithm algorithm = publicKeyObject.getAlgorithm();
        if (SignatureAlgorithm.ES256 != algorithm) {
            return "The provided algorithm is not supported by the server.";
        }

        final CurveType curveType = publicKeyObject.getCurveType();
        if (CurveType.P256 != curveType) {
            return "The provided curve type is not supported by the server.";
        }

        final ECKeyType keyType = publicKeyObject.getKeyType();
        if (ECKeyType.UNCOMPRESSED != keyType) {
            return "The provided key type is not supported by the server.";
        }

        final ECPoint point = publicKeyObject.getPoint();
        if (point == null) {
            return "Missing EC point in public key object.";
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
