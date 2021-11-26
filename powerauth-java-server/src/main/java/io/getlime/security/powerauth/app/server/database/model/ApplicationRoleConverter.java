/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
import java.util.ArrayList;
import java.util.List;

/**
 * Converter for application roles.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Converter
@Component
public class ApplicationRoleConverter implements AttributeConverter<List<String>, String> {

    private static final Logger logger = LoggerFactory.getLogger(ApplicationRoleConverter.class);

    private static final String EMPTY_ROLES = "[]";

    private final ObjectMapper objectMapper;

    /**
     * Converter constructor.
     * @param objectMapper Object mapper.
     */
    public ApplicationRoleConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String convertToDatabaseColumn(List<String> roles) {
        if (roles == null) {
            return EMPTY_ROLES;
        }
        try {
            return objectMapper.writeValueAsString(roles);
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for application roles, error: " + ex.getMessage(), ex);
            return EMPTY_ROLES;
        }
    }

    @Override
    public List<String> convertToEntityAttribute(String roles) {
        if (roles == null) {
            return new ArrayList<>();
        }
        try {
            return objectMapper.readValue(roles, new TypeReference<List<String>>(){});
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for application roles, error: " + ex.getMessage(), ex);
            return new ArrayList<>();
        }

    }
}
