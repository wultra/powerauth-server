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
package io.getlime.security.powerauth.app.server.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Converter for {@link KeyValue} to {@link String}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class KeyValueMapConverter {

    private final ObjectMapper objectMapper;

    /**
     * Converter constructor.
     * @param objectMapper Object mapper.
     */
    public KeyValueMapConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Convert {@link List<KeyValue>} to {@link String}.
     * @param keyValueMap KeyValueMap.
     * @return String value of KeyValueMap in JSON format.
     */
    public String toString(List<KeyValue> keyValueMap) {
        if (keyValueMap == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(keyValueMap);
        } catch (JsonProcessingException ex) {
            logger.error("Unable to serialize JSON payload.", ex);
            return null;
        }
    }

    /**
     * Convert {@link String} to {@link KeyValue}.
     * @param s String value of KeyValueMap in JSON format.
     * @return Constructed KeyValueMap.
     */
    public List<KeyValue> fromString(String s) {
        if (s == null || s.isEmpty()) {
            return new ArrayList<>();
        }
        try {
            return objectMapper.readValue(s, new TypeReference<>(){});
        } catch (IOException ex) {
            logger.error("Unable to parse JSON payload.", ex);
            return new ArrayList<>();
        }
    }

}
