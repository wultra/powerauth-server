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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.wultra.powerauth.fido2.errorhandling.Fido2DeserializationException;
import com.wultra.powerauth.fido2.rest.model.entity.AttestationObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.Serial;
import java.util.Base64;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class AttestationObjectDeserializer extends StdDeserializer<AttestationObject> {

    @Serial
    private static final long serialVersionUID = -5549850902593127253L;

    private final CBORMapper cborMapper = new CBORMapper();

    public AttestationObjectDeserializer() {
        this(null);
    }

    public AttestationObjectDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public AttestationObject deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws Fido2DeserializationException {
        try {
            final String originalTextValue = jsonParser.getText();
            final byte[] decodedAttestationObject = Base64.getDecoder().decode(originalTextValue);
            final AttestationObject attestationObject = cborMapper.readValue(decodedAttestationObject, AttestationObject.class);
            attestationObject.setEncoded(originalTextValue);
            return attestationObject;
        } catch (IOException e) {
            logger.debug(e.getMessage(), e);
            throw new Fido2DeserializationException(e.getMessage(), e);
        }
    }

}
