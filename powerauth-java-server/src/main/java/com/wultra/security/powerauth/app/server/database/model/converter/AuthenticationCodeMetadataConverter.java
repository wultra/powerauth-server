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

package com.wultra.security.powerauth.app.server.database.model.converter;

import com.wultra.security.powerauth.app.server.database.model.AuthenticationCodeMetadata;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * A JPA attribute converter for converting AuthenticationMetadata objects to and from JSON representations.
 * This class enables storing AuthenticationMetadata in the database as a JSON column.
 *
 * @author Jan Dusil
 */
@Converter
@Component
@AllArgsConstructor
@Slf4j
public class AuthenticationCodeMetadataConverter implements AttributeConverter<AuthenticationCodeMetadata, String> {

    private final ObjectMapper objectMapper;

    /**
     * Converts an AuthenticationMetadata object to its JSON string representation.
     *
     * @param attribute The AuthenticationMetadata object to convert.
     * @return The JSON string representation of the object.
     */
    @Override
    public String convertToDatabaseColumn(AuthenticationCodeMetadata attribute) {
        if (attribute == null) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JacksonException ex) {
            logger.warn("JSON writing error", ex);
            return "{}";
        }
    }

    /**
     * Converts a JSON string representation to a AuthenticationMetadata object.
     *
     * @param s The JSON string to convert.
     * @return The converted AuthCodeMetadata object.
     */
    @Override
    public AuthenticationCodeMetadata convertToEntityAttribute(String s) {
        if (StringUtils.isBlank(s)) {
            return null;
        }
        try {
            return objectMapper.readValue(s, new TypeReference<>() {
            });
        } catch (JacksonException ex) {
            logger.warn("Conversion failed for AuthenticationMetadata, error: {}", ex.getMessage(), ex);
            return null;
        }
    }
}