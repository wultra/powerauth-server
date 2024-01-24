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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.wultra.powerauth.fido2.errorhandling.Fido2DeserializationException;
import com.wultra.powerauth.fido2.rest.model.entity.AttestationStatement;
import com.wultra.powerauth.fido2.rest.model.enumeration.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.Serial;
import java.util.Map;

/**
 * JSON deserializer for the attestation statement.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class AttestationStatementDeserializer extends StdDeserializer<AttestationStatement> {

    @Serial
    private static final long serialVersionUID = -3598363993363470844L;

    /**
     * Default deserializer constructor.
     */
    public AttestationStatementDeserializer() {
        this(null);
    }

    /**
     * Deserializer constructor with value class parameter.
     * @param vc Value class.
     */
    public AttestationStatementDeserializer(Class<AttestationStatement> vc) {
        super(vc);
    }

    /**
     * Deserialize the FIDO2 attestation object from JSON request.
     * @param jsonParser JSON parser.
     * @param deserializationContext Deserialization context.
     * @return Deserialized FIDO2 attestation statement.
     * @throws Fido2DeserializationException Thrown in case JSON deserialization fails.
     */
    @Override
    public AttestationStatement deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws Fido2DeserializationException {
        try {
            final Map<String, Object> map = jsonParser.readValueAs(new TypeReference<>() {});
            final AttestationStatement result = new AttestationStatement();
            final Integer alg = (Integer) map.get("alg");
            if (alg != null && -7 == alg) {
                result.setAlgorithm(SignatureAlgorithm.ES256);
            } else {
                result.setAlgorithm(SignatureAlgorithm.UNKNOWN);
            }
            result.setSignature((byte[]) map.get("sig"));
            return result;
        } catch (IOException e) {
            logger.debug(e.getMessage(), e);
            throw new Fido2DeserializationException(e.getMessage(), e);
        }
    }
}
