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

package io.getlime.security.powerauth.app.server.database.model.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.app.server.database.model.SignatureMetadata;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Converts between SignatureMetadata object and JSON serialized
 * storage in database column.
 *
 * @author Your Name
 */
@Converter
@Component
public class SignatureMetadataConverter implements AttributeConverter<SignatureMetadata, String> {

    private static final Logger logger = LoggerFactory.getLogger(SignatureMetadataConverter.class);

    private final ObjectMapper objectMapper;

    /**
     * Converter constructor.
     * @param objectMapper Object mapper.
     */
    public SignatureMetadataConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String convertToDatabaseColumn(SignatureMetadata signatureMetadata) {
        if (signatureMetadata == null) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(signatureMetadata);
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for SignatureMetadata, error: " + ex.getMessage(), ex);
            return "{}";
        }
    }

    @Override
    public SignatureMetadata convertToEntityAttribute(String s) {
        if (s == null || s.isEmpty()) {
            return new SignatureMetadata();
        }
        try {
            return objectMapper.readValue(s, SignatureMetadata.class);
        } catch (JsonProcessingException ex) {
            logger.warn("Conversion failed for SignatureMetadata, error: " + ex.getMessage(), ex);
            return new SignatureMetadata();
        }
    }

}
