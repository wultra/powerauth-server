/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

import com.wultra.powerauth.fido2.rest.model.converter.serialization.AttestationObjectDeserializer;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.CollectedClientDataDeserializer;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.Fido2DeserializationException;
import com.wultra.powerauth.fido2.rest.model.entity.AttestationObject;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import com.wultra.powerauth.fido2.rest.model.request.RegistrationRequestWrapper;
import com.wultra.security.powerauth.fido2.model.request.RegistrationRequest;
import org.springframework.util.Assert;

/**
 * Convert {@link RegistrationRequest} into {@link com.wultra.powerauth.fido2.rest.model.request.RegistrationRequestWrapper}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public final class RegistrationRequestWrapperConverter {

    private RegistrationRequestWrapperConverter() {
        throw new IllegalStateException("Should not be instantiated");
    }

    /**
     * Convert the given request into a wrapper.
     *
     * @param source registration request
     * @return wrapped registration request
     */
    public static RegistrationRequestWrapper convert(final RegistrationRequest source) throws Fido2DeserializationException {
        Assert.notNull(source, "Source must not be null");

        final CollectedClientData clientDataJSON = CollectedClientDataDeserializer.deserialize(source.getAuthenticatorParameters().getResponse().getClientDataJSON());
        final AttestationObject attestationObject = AttestationObjectDeserializer.deserialize(source.getAuthenticatorParameters().getResponse().getAttestationObject());

        return RegistrationRequestWrapper.builder()
                .registrationRequest(source)
                .clientDataJSON(clientDataJSON)
                .attestationObject(attestationObject)
                .build();
    }
}
