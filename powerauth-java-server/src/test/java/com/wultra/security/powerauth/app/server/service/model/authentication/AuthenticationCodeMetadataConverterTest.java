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
package com.wultra.security.powerauth.app.server.service.model.authentication;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.database.model.PowerAuthAuthenticationCodeMetadata;
import com.wultra.security.powerauth.app.server.database.model.AuthenticationCodeMetadata;
import com.wultra.security.powerauth.app.server.database.model.converter.AuthenticationCodeMetadataConverter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for AuthCodeMetadataConverter.
 * This class tests various aspects of converting AuthMetadata to and from its serialized JSON form.
 *
 * @author Jan Dusil
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthenticationCodeMetadataConverterTest {

    @Autowired
    private AuthenticationCodeMetadataConverter converter;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Tests the conversion of a PowerAuthAuthCodeMetadata object to its serialized JSON form.
     */
    @Test
    void convertToDatabaseColumnTest() throws Exception {
        PowerAuthAuthenticationCodeMetadata metadata = new PowerAuthAuthenticationCodeMetadata("POST", "123");
        String jsonStr = converter.convertToDatabaseColumn(metadata);

        assertNotNull(jsonStr);
        final JsonNode node = objectMapper.readTree(jsonStr);
        assertEquals("POWERAUTH", node.get("type").asText());
        assertEquals("POST", node.get("authDataMethod").asText());
        assertEquals("123", node.get("authDataUriId").asText());
    }

    /**
     * Tests the conversion of a serialized JSON string back to a PowerAuthAuthenticationMetadata object.
     */
    @Test
    void convertToEntityAttributeTest() {
        String jsonStr = "{\"type\":\"POWERAUTH\",\"authDataMethod\":\"POST\",\"authDataUriId\":\"123\"}";
        PowerAuthAuthenticationCodeMetadata metadata = (PowerAuthAuthenticationCodeMetadata) converter.convertToEntityAttribute(jsonStr);

        assertNotNull(metadata);
        assertEquals("POST", metadata.getAuthDataMethod());
        assertEquals("123", metadata.getAuthDataUriId());
    }

    /**
     * Tests a round-trip conversion, from object to JSON string and back to object, to ensure consistency.
     */
    @Test
    void testRoundTripConversion() {
        PowerAuthAuthenticationCodeMetadata originalMetadata = new PowerAuthAuthenticationCodeMetadata("POST", "123");
        String jsonStr = converter.convertToDatabaseColumn(originalMetadata);
        PowerAuthAuthenticationCodeMetadata convertedMetadata = (PowerAuthAuthenticationCodeMetadata) converter.convertToEntityAttribute(jsonStr);

        assertNotNull(convertedMetadata);
        assertEquals(originalMetadata.getAuthDataMethod(), convertedMetadata.getAuthDataMethod());
        assertEquals(originalMetadata.getAuthDataUriId(), convertedMetadata.getAuthDataUriId());
    }

    /**
     * Tests the converter's behavior when provided with an invalid JSON string.
     */
    @Test
    void testInvalidJsonInput() {
        String invalidJson = "{\"invalidField\":\"someValue\"}";
        AuthenticationCodeMetadata metadata = converter.convertToEntityAttribute(invalidJson);
        assertNull(metadata);
    }
}
