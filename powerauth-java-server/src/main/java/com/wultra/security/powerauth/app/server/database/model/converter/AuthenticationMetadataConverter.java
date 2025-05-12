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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.database.model.AuthenticationMetadata;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * A JPA attribute converter for converting AuthenticationMetadata objects to and from JSON representations.
 * This class enables storing AuthenticationMetadata in the database as a JSON column.
 *
 * @author Jan Dusil
 */
@Converter
@Component
@Slf4j
public class AuthenticationMetadataConverter implements AttributeConverter<AuthenticationMetadata, String> {

    private final ObjectMapper objectMapper;

    /**
     * No-arg constructor that initializes a default ObjectMapper.
     */
    public AuthenticationMetadataConverter() {
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Constructor that initializes the ObjectMapper.
     *
     * @param objectMapper The Jackson ObjectMapper.
     */
    @Autowired
    public AuthenticationMetadataConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Converts an AuthenticationMetadata object to its JSON string representation.
     *
     * @param attribute The AuthenticationMetadata object to convert.
     * @return The JSON string representation of the object.
     */
    @Override
    public String convertToDatabaseColumn(AuthenticationMetadata attribute) {
        if (attribute == null) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException ex) {
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
    public AuthenticationMetadata convertToEntityAttribute(String s) {
        if (StringUtils.isBlank(s)) {
            return null;
        }
        try {
            return objectMapper.readValue(s, new TypeReference<>() {
            });
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for AuthenticationMetadata, error: {}", ex.getMessage(), ex);
            return null;
        }
    }
}