/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.wultra.security.powerauth.fido2.model.converter.serialization.Base64UrlToBase64Deserializer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link Base64UrlToBase64Deserializer}.
 *
 * @author Pavel Sindelar, pavel.sindelar@wultra.com
 */
class Base64UrlToBase64DeserializerTest {

    private static ObjectMapper objectMapper;

    @BeforeAll
    static void setUp() {
        final SimpleModule module = new SimpleModule();
        module.addDeserializer(String.class, new Base64UrlToBase64Deserializer());
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(module);
    }

    @Test
    void testDeserialize_base64UrlWithoutPadding_convertedToBase64() throws Exception {
        final String result = objectMapper.readValue("\"-_--\"", String.class);
        assertEquals("+/++", result);
    }

    @Test
    void testDeserialize_base64UrlMissingPadding_paddingAdded() throws Exception {
        final String result = objectMapper.readValue("\"SGVsbG8\"", String.class);
        assertEquals("SGVsbG8=", result);
    }

    @Test
    void testDeserialize_alreadyStandardBase64_returnedUnchanged() throws Exception {
        final String result = objectMapper.readValue("\"SGVsbG8=\"", String.class);
        assertEquals("SGVsbG8=", result);
    }

    @Test
    void testDeserialize_alreadyStandardBase64NoPaddingNeeded_returnedUnchanged() throws Exception {
        final String result = objectMapper.readValue("\"ABCDEFGH\"", String.class);
        assertEquals("ABCDEFGH", result);
    }

    @Test
    void testDeserialize_null_returnsNull() throws Exception {
        final String result = objectMapper.readValue("null", String.class);
        assertNull(result);
    }

    @Test
    void testDeserialize_dashOnly_convertedToPlus() throws Exception {
        final String result = objectMapper.readValue("\"AA-A\"", String.class);
        assertEquals("AA+A", result);
    }

    @Test
    void testDeserialize_underscoreOnly_convertedToSlash() throws Exception {
        final String result = objectMapper.readValue("\"AA_A\"", String.class);
        assertEquals("AA/A", result);
    }

    @Test
    void testDeserialize_invalidLength_throwsException() {
        assertThrows(JsonMappingException.class, () -> objectMapper.readValue("\"A\"", String.class));
    }
}
