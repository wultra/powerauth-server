/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Base64;

/**
 * Converter for server public keys which handles key conversion.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class PublicKeysConverter {

    private final ObjectMapper objectMapper;

    @Autowired
    public PublicKeysConverter(@Qualifier("publicKeyObjectMapper") ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Convert server public keys from database value to object.
     * @param serverPublicKeysBase64 Server public keys encoded in Base64-encoding.
     * @return Server public keys
     */
    public PublicKeyRegistry fromDBValue(final String serverPublicKeysBase64) throws GenericServiceException {
        try {
            final byte[] data = convertFromBase64(serverPublicKeysBase64);
            return deserialize(data);
        } catch (IOException e) {
            logger.warn(e.getMessage(), e);
            throw new GenericServiceException(ServiceError.INVALID_KEY_FORMAT, e.getMessage());
        }
    }

    /**
     * Convert public keys to database value.
     * @param publicKeys Public keys.
     * @return Public keys database value.
     * @throws GenericServiceException Thrown when public keys encryption fails.
     */
    public String toDBValue(final PublicKeyRegistry publicKeys) throws GenericServiceException {
        try {
            return convertToBase64(serialize(publicKeys));
        } catch (IOException e) {
            logger.warn(e.getMessage(), e);
            throw new GenericServiceException(ServiceError.INVALID_KEY_FORMAT, e.getMessage());
        }
    }

    /**
     * Serialize public key registry to bytes.
     * @param source Public key registry.
     * @return Byte array with serialized JSON.
     * @throws JsonProcessingException In case conversion fails.
     */
    public byte[] serialize(final PublicKeyRegistry source) throws JsonProcessingException {
        return objectMapper.writeValueAsBytes(source);
    }

    /**
     * Deserialize public key registry from bytes.
     * @param source Byte array with JSON representation.
     * @return Public key registry.
     * @throws IOException In case conversion fails.
     */
    public PublicKeyRegistry deserialize(final byte[] source) throws IOException {
        return objectMapper.readValue(source, PublicKeyRegistry.class);
    }

    private String convertToBase64(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private byte[] convertFromBase64(final String source) {
        return Base64.getDecoder().decode(source);
    }

}
