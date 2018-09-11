/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Lime - HighTech Solutions s.r.o.
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
import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.KeyValueMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Converter for {@link KeyValueMap} to {@link String}.
 *
 * @author Roman Strobl, roman.strobl@lime-company.eu
 */
public class KeyValueMapConverter {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger logger = LoggerFactory.getLogger(KeyValueMapConverter.class);

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
            return mapper.writeValueAsString(keyValueMap);
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
            return mapper.readValue(s, KeyValueMap.class);
        } catch (IOException ex) {
            logger.error("Unable to parse JSON payload.", ex);
            return new KeyValueMap();
        }
    }
}
