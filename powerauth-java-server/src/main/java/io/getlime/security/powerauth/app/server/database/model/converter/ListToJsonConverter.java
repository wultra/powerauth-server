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

package io.getlime.security.powerauth.app.server.database.model.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

/**
 * Converts between list of strings and JSON serialized storage in a database column.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Converter
@Component
@Slf4j
public class ListToJsonConverter implements AttributeConverter<List<String>, String> {

    private static final String EMPTY_LIST = "[]";

    private final ObjectMapper objectMapper;

    /**
     * Converter constructor.
     * @param objectMapper Object mapper.
     */
    public ListToJsonConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String convertToDatabaseColumn(List<String> attributes) {
        if (attributes == null) {
            return EMPTY_LIST;
        }
        try {
            return objectMapper.writeValueAsString(attributes);
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for attribute list, error: {}", ex.getMessage(), ex);
            return EMPTY_LIST;
        }
    }

    @Override
    public List<String> convertToEntityAttribute(String dbValue) {
        if (dbValue == null) {
            return null;
        }
        try {
            return objectMapper.readValue(dbValue, new TypeReference<>() {});
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for attribute list, error: {}", ex.getMessage(), ex);
            return Collections.emptyList();
        }
    }

}
