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
import com.wultra.core.http.common.headers.UserAgent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * * Test for {@link MapToJsonConverter}.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */

class MapToJsonConverterTest {
    private MapToJsonConverter converter;

    @BeforeEach
    void setUp() {
        final ObjectMapper objectMapper = new ObjectMapper();
        converter = new MapToJsonConverter(objectMapper);
    }

    /**
     * Tests the conversion of a map containing serializable objects, including a complex object,
     * to a JSON string for database storage.
     * Verifies that the complex object is correctly serialized and the resulting JSON string
     * matches the expected format.
     */
    @Test
    void testConvertToDatabaseColumnSerializableObject() {
        Map<String, Object> testMap = new HashMap<>();
        testMap.put("key1", "value1");
        final String exampleRequestUserAgent = "PowerAuthNetworking/1.1.7 (en; cellular) com.wultra.app.MobileToken.wtest/2.0.0 (Apple; iOS/16.6.1; iphone12,3)";
        UserAgent.parse(exampleRequestUserAgent).ifPresent(device -> testMap.put("key2", device));

        final String jsonResult = converter.convertToDatabaseColumn(testMap);
        assertNotNull(jsonResult);
        assertFalse(jsonResult.isEmpty());
        assertEquals("{\"key1\":\"value1\"," +
                "\"key2\":{\"networkVersion\":\"1.1.7\"," +
                "\"language\":\"en\"," +
                "\"connection\":\"cellular\"," +
                "\"product\":\"com.wultra.app.MobileToken.wtest\"," +
                "\"version\":\"2.0.0\"," +
                "\"platform\":\"Apple\"," +
                "\"os\":\"iOS\"," +
                "\"osVersion\":\"16.6.1\"," +
                "\"model\":\"iphone12,3\"}}", jsonResult);
    }


    /**
     * Tests the conversion of a simple map to a JSON string for database storage.
     * Verifies that the map is correctly serialized and the resulting JSON string
     * matches the expected format.
     */
    @Test
    void testConvertToDatabaseColumn() {
        Map<String, Object> testMap = new HashMap<>();
        testMap.put("key1", "value1");
        testMap.put("key2", 42);

        final String jsonResult = converter.convertToDatabaseColumn(testMap);
        assertNotNull(jsonResult);
        assertFalse(jsonResult.isEmpty());
        assertEquals("{\"key1\":\"value1\",\"key2\":42}", jsonResult);
    }

    /**
     * Tests the conversion behavior when a null map is provided.
     * Verifies that the converter returns an empty JSON object string.
     */
    @Test
    void testConvertToDatabaseColumnWithNull() {
        final String jsonResult = converter.convertToDatabaseColumn(null);
        assertNotNull(jsonResult);
        assertEquals("{}", jsonResult);
    }

    /**
     * Tests the conversion of a JSON string back to a map of serializable objects.
     * Verifies that the JSON string is correctly deserialized and the resulting map
     * contains the expected values.
     */
    @Test
    void testConvertToEntityAttribute() throws JsonProcessingException {
        final String jsonString = "{\"key1\":\"value1\",\"key2\":42}";
        final Map<String, Object> resultMap = converter.convertToEntityAttribute(jsonString);

        assertNotNull(resultMap);
        assertFalse(resultMap.isEmpty());
        assertEquals("value1", resultMap.get("key1"));
        assertEquals(42, resultMap.get("key2"));
    }

    /**
     * Tests the conversion behavior when a null JSON string is provided.
     * Verifies that the converter returns an empty map.
     */
    @Test
    void testConvertToEntityAttributeWithNull() {
        final Map<String, Object> resultMap = converter.convertToEntityAttribute(null);
        assertNotNull(resultMap);
        assertTrue(resultMap.isEmpty());
    }

    /**
     * Tests the conversion behavior with an invalid JSON string.
     * Verifies that the converter handles the invalid JSON gracefully and returns an empty map.
     */
    @Test
    void testConvertToEntityAttributeWithInvalidJson() {
        final String invalidJsonString = "This is not a valid JSON";
        final Map<String, Object> resultMap = converter.convertToEntityAttribute(invalidJsonString);

        assertNotNull(resultMap);
        assertTrue(resultMap.isEmpty());
    }
}
