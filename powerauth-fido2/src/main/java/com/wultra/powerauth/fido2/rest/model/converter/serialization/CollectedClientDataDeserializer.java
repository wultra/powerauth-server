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

package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Deserializer for FIDO2 {@link CollectedClientData}.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Slf4j
public final class CollectedClientDataDeserializer {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private CollectedClientDataDeserializer() {
        throw new IllegalStateException("Should not be instantiated");
    }

    /**
     * Deserialize the FIDO2 CollectedClientData object from the given string.
     *
     * @param source base64 encoded string
     * @return collectClientData or {@code null}
     */
    public static CollectedClientData deserialize(final String source) {
        Assert.notNull(source, "Source must not be null");

        final byte[] decodedClientDataJSON = Base64.getDecoder().decode(source);
        final CollectedClientData collectedClientData = OBJECT_MAPPER.readValue(decodedClientDataJSON, CollectedClientData.class);
        collectedClientData.setEncoded(new String(decodedClientDataJSON, StandardCharsets.UTF_8));
        return collectedClientData;
    }

}
