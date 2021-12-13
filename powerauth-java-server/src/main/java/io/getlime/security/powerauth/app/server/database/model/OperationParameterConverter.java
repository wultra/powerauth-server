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

package io.getlime.security.powerauth.app.server.database.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.util.HashMap;
import java.util.Map;

/**
 * Converts between operation parameter map and JSON serialized
 * storage in database column.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Converter
@Component
public class OperationParameterConverter implements AttributeConverter<Map<String, String>, String> {

    private static final Logger logger = LoggerFactory.getLogger(OperationParameterConverter.class);

    private static final String EMPTY_PARAMS = "{}";

    private final ObjectMapper objectMapper;

    /**
     * Converter constructor.
     * @param objectMapper Object mapper.
     */
    public OperationParameterConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String convertToDatabaseColumn(Map<String, String> parameters) {
        if (parameters == null) {
            return EMPTY_PARAMS;
        }
        try {
            return objectMapper.writeValueAsString(parameters);
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for operation parameters, error: " + ex.getMessage(), ex);
            return EMPTY_PARAMS;
        }
    }

    @Override
    public Map<String, String> convertToEntityAttribute(String s) {
        if (s == null) {
            return new HashMap<>();
        }
        try {
            return objectMapper.readValue(s, new TypeReference<Map<String, String>>(){});
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for operation parameters, error: " + ex.getMessage(), ex);
            return new HashMap<>();
        }
    }

}
