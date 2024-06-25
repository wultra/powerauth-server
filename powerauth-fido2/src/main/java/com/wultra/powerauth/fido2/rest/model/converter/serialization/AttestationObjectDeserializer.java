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

package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.wultra.powerauth.fido2.rest.model.entity.AttestationObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Base64;

/**
 * Deserializer for {@link AttestationObject}.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Slf4j
public final class AttestationObjectDeserializer {

    private static final CBORMapper CBOR_MAPPER = new CBORMapper();

    private AttestationObjectDeserializer() {
        throw new IllegalStateException("Should not be instantiated");
    }

    /**
     * Deserialize the FIDO2 attestation object from the given string.
     *
     * @param source base64 encoded string.
     * @return Deserialized FIDO2 attestation object or {@code null}
     * @throws Fido2DeserializationException Thrown in case JSON deserialization fails.
     */
    public static AttestationObject deserialize(final String source) throws Fido2DeserializationException {
        Assert.notNull(source, "Source must not be null");

        try {
            final byte[] decodedAttestationObject = Base64.getDecoder().decode(source);
            final AttestationObject attestationObject = CBOR_MAPPER.readValue(decodedAttestationObject, AttestationObject.class);
            attestationObject.setEncoded(source);
            return attestationObject;
        } catch (IOException e) {
            logger.debug(e.getMessage(), e);
            throw new Fido2DeserializationException(e.getMessage(), e);
        }
    }

}
