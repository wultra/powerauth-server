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

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.Serial;
import java.util.Base64;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class CollectedClientDataDeserializer extends StdDeserializer<CollectedClientData> {

    @Serial
    private static final long serialVersionUID = 8991171442005200006L;
    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public CollectedClientDataDeserializer() {
        this(null);
    }

    public CollectedClientDataDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public CollectedClientData deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) {
        try {
            final String originalTextValue = jsonParser.getText();
            final byte[] decodedClientDataJSON = Base64.getDecoder().decode(originalTextValue);
            final CollectedClientData collectedClientData = objectMapper.readValue(decodedClientDataJSON, CollectedClientData.class);
            collectedClientData.setEncoded(new String(decodedClientDataJSON));
            return collectedClientData;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
