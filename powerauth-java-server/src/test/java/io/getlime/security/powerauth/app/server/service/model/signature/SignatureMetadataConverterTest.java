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
package io.getlime.security.powerauth.app.server.service.model.signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.app.server.database.model.PowerAuthSignatureMetadata;
import io.getlime.security.powerauth.app.server.database.model.SignatureMetadata;
import io.getlime.security.powerauth.app.server.database.model.converter.SignatureMetadataConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Test class for SignatureMetadataConverter.
 * This class tests various aspects of converting SignatureMetadata to and from its serialized JSON form.
 *
 * @author Jan Dusil
 */
public class SignatureMetadataConverterTest {

    /**
     * Converter object to be used for tests.
     */
    private SignatureMetadataConverter converter;

    /**
     * Initializes the SignatureMetadataConverter object and any other necessary objects.
     */
    @BeforeEach
    void setUp() {
        converter = new SignatureMetadataConverter();
    }

    /**
     * Tests the conversion of a PowerAuthSignatureMetadata object to its serialized JSON form.
     */
    @Test
    void convertToDatabaseColumnTest() {
        PowerAuthSignatureMetadata metadata = new PowerAuthSignatureMetadata("POST", "123");
        String jsonStr = converter.convertToDatabaseColumn(metadata);

        assertNotNull(jsonStr);
        assertEquals("{\"type\":\"POWERAUTH\",\"signatureDataMethod\":\"POST\",\"signatureDataUriId\":\"123\"}", jsonStr);
    }

    /**
     * Tests the conversion of a serialized JSON string back to a SignatureMetadata object.
     */
    @Test
    void convertToEntityAttributeTest() {
        String jsonStr = "{\"type\":\"POWERAUTH\",\"signatureDataMethod\":\"POST\",\"signatureDataUriId\":\"123\"}";
        PowerAuthSignatureMetadata metadata = (PowerAuthSignatureMetadata) converter.convertToEntityAttribute(jsonStr);

        assertNotNull(metadata);
        assertEquals("POST", metadata.getSignatureDataMethod());
        assertEquals("123", metadata.getSignatureDataUriId());
    }

    /**
     * Tests a round-trip conversion, from object to JSON string and back to object, to ensure consistency.
     */
    @Test
    void testRoundTripConversion() {
        PowerAuthSignatureMetadata originalMetadata = new PowerAuthSignatureMetadata("POST", "123");
        String jsonStr = converter.convertToDatabaseColumn(originalMetadata);
        PowerAuthSignatureMetadata convertedMetadata = (PowerAuthSignatureMetadata) converter.convertToEntityAttribute(jsonStr);

        assertNotNull(convertedMetadata);
        assertEquals(originalMetadata.getSignatureDataMethod(), convertedMetadata.getSignatureDataMethod());
        assertEquals(originalMetadata.getSignatureDataUriId(), convertedMetadata.getSignatureDataUriId());
    }

    /**
     * Tests the converter's behavior when provided with an invalid JSON string.
     */
    @Test
    void testInvalidJsonInput() {
        String invalidJson = "{\"invalidField\":\"someValue\"}";
        SignatureMetadata<String, Object> metadata = (PowerAuthSignatureMetadata) converter.convertToEntityAttribute(invalidJson);
        assertNull(metadata);
    }
}
