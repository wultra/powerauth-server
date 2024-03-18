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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.wultra.powerauth.fido2.rest.model.entity.Fido2Authenticators;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorParameters;
import com.wultra.powerauth.fido2.rest.model.entity.RegistrationChallenge;
import com.wultra.powerauth.fido2.rest.model.request.RegistrationRequest;
import com.wultra.powerauth.fido2.rest.model.response.RegistrationResponse;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Converter class for registration related objects.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class RegistrationConverter {

    /**
     * Convert registration challenge to authenticator detail.
     * @param challenge Registration challenge.
     * @param requestObject Registration request.
     * @param aaguid AAGUID bytes.
     * @param publicKey Public key bytes.
     * @return Authenticator detail, if present.
     */
    public Optional<AuthenticatorDetail> convert(RegistrationChallenge challenge, RegistrationRequest requestObject, byte[] aaguid, byte[] publicKey) {
        try {
            final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
            authenticatorDetail.setUserId(challenge.getUserId());
            authenticatorDetail.setActivationId(challenge.getActivationId());
            authenticatorDetail.setApplicationId(challenge.getApplicationId());

            final Fido2Authenticators.Model model = Fido2Authenticators.modelByAaguid(aaguid);

            authenticatorDetail.setCredentialId(requestObject.getAuthenticatorParameters().getCredentialId());
            authenticatorDetail.setExtras(convertExtras(requestObject));
            authenticatorDetail.setActivationName(requestObject.getActivationName());
            authenticatorDetail.setPlatform(requestObject.getAuthenticatorParameters().getAuthenticatorAttachment());
            authenticatorDetail.setDeviceInfo(model.description());
            authenticatorDetail.setActivationStatus(ActivationStatus.ACTIVE);
            authenticatorDetail.setActivationFlags(new ArrayList<>());
            authenticatorDetail.setApplicationRoles(new ArrayList<>());
            authenticatorDetail.setPublicKeyBytes(publicKey);
            authenticatorDetail.setFailedAttempts(0L);
            authenticatorDetail.setMaxFailedAttempts(5L);
            return Optional.of(authenticatorDetail);
        } catch (JsonProcessingException e) {
            logger.warn(e.getMessage(), e);
            return Optional.empty();
        }
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

    private Map<String, Object> convertExtras(RegistrationRequest requestObject) throws JsonProcessingException {
        final AuthenticatorParameters authenticatorParameters = requestObject.getAuthenticatorParameters();
        final Map<String, Object> params = new HashMap<>();
        params.put("relyingPartyId", authenticatorParameters.getRelyingPartyId());
        params.put("authenticatorAttachment", authenticatorParameters.getAuthenticatorAttachment());
        params.put("credentialId", authenticatorParameters.getResponse().getAttestationObject().getAuthData().getAttestedCredentialData().getCredentialId());
        params.put("origin", authenticatorParameters.getResponse().getClientDataJSON().getOrigin());
        params.put("topOrigin", authenticatorParameters.getResponse().getClientDataJSON().getTopOrigin());
        params.put("isCrossOrigin", authenticatorParameters.getResponse().getClientDataJSON().isCrossOrigin());
        params.put("aaguid", authenticatorParameters.getResponse().getAttestationObject().getAuthData().getAttestedCredentialData().getAaguid());
        params.put("transports", authenticatorParameters.getResponse().getTransports());
        return params;
    }

}
