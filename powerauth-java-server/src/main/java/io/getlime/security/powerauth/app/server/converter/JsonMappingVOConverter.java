/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
public class JsonMappingVOConverter {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger logger = LoggerFactory.getLogger(JsonMappingVOConverter.class);

    /**
     * Convert {@link Object} to {@link String}.
     * @param obj Object.
     * @return String value of KeyValueMap in JSON format.
     */
    public String writeToString(Object obj) {
        if (obj == null) {
            return null;
        }
        try {
            return mapper.writeValueAsString(obj);
        } catch (JsonProcessingException ex) {
            logger.error("Unable to serialize JSON payload.", ex);
            return null;
        }
    }

    /**
     * Convert {@link String} to {@link Map}.
     * @param s String value of KeyValueMap in JSON format.
     * @return Constructed KeyValueMap.
     */
    public Map<String, Object> mapFromString(String s) {
        if (s == null || s.isEmpty()) {
            return new HashMap<>();
        }
        try {
            return mapper.readValue(s, new TypeReference<Map<String,Object>>() {});
        } catch (IOException ex) {
            logger.error("Unable to parse JSON payload.", ex);
            return new HashMap<>();
        }
    }

}
