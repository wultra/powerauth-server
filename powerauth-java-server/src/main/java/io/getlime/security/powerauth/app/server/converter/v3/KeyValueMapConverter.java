/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.converter.v3;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.v3.KeyValueMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

/**
 * Converter for {@link KeyValueMap} to {@link String}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class KeyValueMapConverter {

    private static final Logger logger = LoggerFactory.getLogger(KeyValueMapConverter.class);

    private final ObjectMapper objectMapper;

    /**
     * Converter constructor.
     * @param objectMapper Object mapper.
     */
    public KeyValueMapConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Convert {@link KeyValueMap} to {@link String}.
     * @param keyValueMap KeyValueMap.
     * @return String value of KeyValueMap in JSON format.
     */
    public String toString(KeyValueMap keyValueMap) {
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
     * Convert {@link String} to {@link KeyValueMap}.
     * @param s String value of KeyValueMap in JSON format.
     * @return Constructed KeyValueMap.
     */
    public KeyValueMap fromString(String s) {
        if (s == null || s.isEmpty()) {
            return new KeyValueMap();
        }
        try {
            return objectMapper.readValue(s, KeyValueMap.class);
        } catch (IOException ex) {
            logger.error("Unable to parse JSON payload.", ex);
            return new KeyValueMap();
        }
    }

    /**
     * Convert PowerAuth version 2.0 KeyValueMap to version 3.0 KeyValueMap.
     * @param keyValueMap Version 2.0 KeyValueMap to convert.
     * @return Converted KeyValueMap in version 3.0.
     */
    public KeyValueMap fromKeyValueMap(com.wultra.security.powerauth.client.v2.KeyValueMap keyValueMap) {
        KeyValueMap result = new KeyValueMap();
        List<KeyValueMap.Entry> entriesV3 = result.getEntry();
        for (com.wultra.security.powerauth.client.v2.KeyValueMap.Entry entryV2: keyValueMap.getEntry()) {
            KeyValueMap.Entry entry = new KeyValueMap.Entry();
            entry.setKey(entryV2.getKey());
            entry.setValue(entryV2.getValue());
            entriesV3.add(entry);
        }
        return result;
    }
}
