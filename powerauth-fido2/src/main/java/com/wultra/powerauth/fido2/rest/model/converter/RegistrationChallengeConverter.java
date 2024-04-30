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

import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
import com.wultra.powerauth.fido2.rest.model.entity.Credential;
import com.wultra.powerauth.fido2.rest.model.entity.RegistrationChallenge;
import com.wultra.powerauth.fido2.rest.model.response.RegistrationChallengeResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class RegistrationChallengeConverter {

    /**
     * Convert a new assertion challenge response from a provided challenge.
     *
     * @param source Challenge.
     * @return Assertion challenge response.
     */
    public RegistrationChallengeResponse fromChallenge(RegistrationChallenge source) {
        if (source == null) {
            return null;
        }
        final RegistrationChallengeResponse destination = new RegistrationChallengeResponse();
        destination.setUserId(source.getUserId());
        destination.setActivationId(source.getActivationId());
        destination.setApplicationId(source.getApplicationId());
        destination.setChallenge(source.getChallenge());
        destination.setExcludeCredentials(source.getExcludeCredentials());
        return destination;
    }

    public static Credential toCredentialDescriptor(final AuthenticatorDetail authenticatorDetail) {
        @SuppressWarnings("unchecked")
        final List<String> transports = (List<String>) authenticatorDetail.getExtras().get("transports");
        final byte[] credentialId = Base64.getDecoder().decode(authenticatorDetail.getCredentialId());

        return Credential.builder()
                .credentialId(credentialId)
                .transports(transports)
                .build();
    }

}
