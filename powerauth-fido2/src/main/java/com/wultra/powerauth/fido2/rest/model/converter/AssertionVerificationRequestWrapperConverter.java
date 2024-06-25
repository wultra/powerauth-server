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

import com.wultra.powerauth.fido2.rest.model.converter.serialization.AuthenticatorDataDeserializer;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.CollectedClientDataDeserializer;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.Fido2DeserializationException;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorData;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import com.wultra.powerauth.fido2.rest.model.request.AssertionVerificationRequestWrapper;
import com.wultra.security.powerauth.fido2.model.request.AssertionVerificationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * Convert {@link AssertionVerificationRequest} into {@link AssertionVerificationRequestWrapper}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Component
public class AssertionVerificationRequestWrapperConverter {

    /**
     * Convert the given request into a wrapper.
     *
     * @param source assertion verification request
     * @return wrapped registration request
     */
    public AssertionVerificationRequestWrapper convert(final AssertionVerificationRequest source) throws Fido2DeserializationException {
        Assert.notNull(source, "Source must not be null");

        final CollectedClientData clientDataJSON = CollectedClientDataDeserializer.deserialize(source.getResponse().getClientDataJSON());
        final AuthenticatorData authenticatorData = AuthenticatorDataDeserializer.deserialize(source.getResponse().getAuthenticatorData());

        return AssertionVerificationRequestWrapper.builder()
                .assertionVerificationRequest(source)
                .clientDataJSON(clientDataJSON)
                .authenticatorData(authenticatorData)
                .build();
    }
}
