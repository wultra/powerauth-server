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

package com.wultra.powerauth.fido2.rest.model.converter;

import com.wultra.powerauth.fido2.rest.model.entity.AttestationObject;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import com.wultra.powerauth.fido2.rest.model.entity.RegistrationChallenge;
import com.wultra.powerauth.fido2.rest.model.request.RegistrationRequestWrapper;
import com.wultra.powerauth.fido2.service.model.Fido2Authenticator;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorDetail;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorParameters;
import com.wultra.security.powerauth.fido2.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.fido2.model.request.RegistrationRequest;
import com.wultra.security.powerauth.fido2.model.response.RegistrationResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * Converter class for registration related objects.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@AllArgsConstructor
@Slf4j
public class RegistrationConverter {

    /**
     * Convert registration challenge to authenticator detail.
     * @param challenge Registration challenge.
     * @param wrapper Registration request wrapper.
     * @param model FIDO2 Authenticator details.
     * @param publicKey Public key bytes.
     * @return Authenticator detail, if present.
     */
    public AuthenticatorDetail convert(RegistrationChallenge challenge, RegistrationRequestWrapper wrapper, Fido2Authenticator model, byte[] publicKey) {
        final RegistrationRequest requestObject = wrapper.registrationRequest();
        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setUserId(challenge.getUserId());
        authenticatorDetail.setActivationId(challenge.getActivationId());
        authenticatorDetail.setApplicationId(challenge.getApplicationId());
        authenticatorDetail.setCredentialId(requestObject.getAuthenticatorParameters().getCredentialId());
        authenticatorDetail.setExtras(convertExtras(wrapper));
        authenticatorDetail.setActivationName(requestObject.getActivationName());
        authenticatorDetail.setPlatform(requestObject.getAuthenticatorParameters().getAuthenticatorAttachment());
        authenticatorDetail.setDeviceInfo(model.description());
        authenticatorDetail.setActivationStatus(ActivationStatus.ACTIVE);
        authenticatorDetail.setActivationFlags(new ArrayList<>());
        authenticatorDetail.setApplicationRoles(new ArrayList<>());
        authenticatorDetail.setPublicKeyBytes(publicKey);
        authenticatorDetail.setFailedAttempts(0L);
        authenticatorDetail.setMaxFailedAttempts(5L);
        return authenticatorDetail;
    }

    /**
     * Convert authenticator detail to registration response.
     * @param source Authenticator detail.
     * @return Registration response.
     */
    public RegistrationResponse convertRegistrationResponse(AuthenticatorDetail source) {
        final RegistrationResponse result = new RegistrationResponse();
        result.setUserId(source.getUserId());
        result.setActivationId(source.getActivationId());
        result.setApplicationId(source.getApplicationId());
        result.setCredentialId(source.getCredentialId());
        result.setExtras(source.getExtras());
        result.setActivationName(source.getActivationName());
        result.setPlatform(source.getPlatform());
        result.setDeviceInfo(source.getDeviceInfo());
        result.setActivationStatus(source.getActivationStatus());
        result.setActivationFlags(source.getActivationFlags());
        result.setApplicationRoles(source.getApplicationRoles());
        result.setPublicKeyBytes(source.getPublicKeyBytes());
        result.setFailedAttempts(source.getFailedAttempts());
        result.setMaxFailedAttempts(source.getMaxFailedAttempts());
        return result;
    }

    private Map<String, Object> convertExtras(RegistrationRequestWrapper wrapper) {
        final AuthenticatorParameters authenticatorParameters = wrapper.registrationRequest().getAuthenticatorParameters();
        final Map<String, Object> params = new HashMap<>();
        params.put("relyingPartyId", authenticatorParameters.getRelyingPartyId());
        params.put("authenticatorAttachment", authenticatorParameters.getAuthenticatorAttachment());
        final CollectedClientData collectedClientData = wrapper.clientDataJSON();
        final AttestationObject attestationObject = wrapper.attestationObject();
        params.put("credentialId", attestationObject.getAuthData().getAttestedCredentialData().getCredentialId());
        params.put("origin", collectedClientData.getOrigin());
        params.put("topOrigin", collectedClientData.getTopOrigin());
        params.put("isCrossOrigin", collectedClientData.isCrossOrigin());
        final byte[] aaguidBytes = attestationObject.getAuthData().getAttestedCredentialData().getAaguid();
        params.put("aaguid", bytesToUUID(aaguidBytes));
        params.put("transports", authenticatorParameters.getResponse().getTransports());
        return params;
    }

    public UUID bytesToUUID(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        final ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        final long mostSigBits = byteBuffer.getLong();
        final long leastSigBits = byteBuffer.getLong();
        return new UUID(mostSigBits, leastSigBits);
    }

}
