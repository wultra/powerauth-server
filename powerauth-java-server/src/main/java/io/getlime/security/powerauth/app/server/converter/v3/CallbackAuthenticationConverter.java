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
package io.getlime.security.powerauth.app.server.converter.v3;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.v3.HttpAuthenticationPrivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;

/**
 * Converter for callback request authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Converter
@Component
public class CallbackAuthenticationConverter implements AttributeConverter<HttpAuthenticationPrivate, String> {

    private static final Logger logger = LoggerFactory.getLogger(CallbackAuthenticationConverter.class);

    private final ObjectMapper objectMapper;

    /**
     * Converter constructor.
     * @param objectMapper Object mapper.
     */
    public CallbackAuthenticationConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String convertToDatabaseColumn(HttpAuthenticationPrivate authentication) {
        try {
            if (authentication == null) {
                authentication = new HttpAuthenticationPrivate();
            }
            return objectMapper.writeValueAsString(authentication);
        } catch (JsonProcessingException ex) {
            logger.error("Unable to serialize JSON payload", ex);
            return null;
        }

    }

    @Override
    public HttpAuthenticationPrivate convertToEntityAttribute(String authentication) {
        if (authentication == null) {
            return new HttpAuthenticationPrivate();
        }
        try {
            return objectMapper.readValue(authentication, HttpAuthenticationPrivate.class);
        } catch (IOException ex) {
            logger.error("Unable to parse JSON payload", ex);
            return new HttpAuthenticationPrivate();
        }

    }
}
