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

package com.wultra.powerauth.fido2.database.entity.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;

/**
 * Converter between list of strings and JSON serialized storage in a database column.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Converter
@Component
@Slf4j
public class ListToStringConverter implements AttributeConverter<List<String>, String> {

    private static final String EMPTY_LIST = "[]";

    private final ObjectMapper objectMapper;

    public ListToStringConverter(final ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String convertToDatabaseColumn(final List<String> attributes) {
        if (CollectionUtils.isEmpty(attributes)) {
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
    public List<String> convertToEntityAttribute(final String dbValue) {
        if (!StringUtils.hasText(dbValue)) {
            return Collections.emptyList();
        }

        try {
            return objectMapper.readValue(dbValue, new TypeReference<>() {});
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for attribute list, error: {}", ex.getMessage(), ex);
            return Collections.emptyList();
        }
    }

}
