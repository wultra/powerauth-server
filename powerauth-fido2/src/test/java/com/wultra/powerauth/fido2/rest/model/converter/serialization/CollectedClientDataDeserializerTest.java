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
package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link CollectedClientData}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class CollectedClientDataDeserializerTest {

    @Test
    void testDeserialize() throws Exception {
        final CollectedClientData result = CollectedClientDataDeserializer.deserialize("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTTBneVVWVXRUa3BSVWpJdFZUZEpWMEl0UjBkWE5sRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ==");

        assertEquals("""
                {"type":"webauthn.create","challenge":"M0gyUVUtTkpRUjItVTdJV0ItR0dXNlE","origin":"http://localhost"}
                """.strip(), result.getEncoded());
        assertEquals("webauthn.create", result.getType());
        assertEquals("3H2QU-NJQR2-U7IWB-GGW6Q", result.getChallenge());
        assertEquals("http://localhost", result.getOrigin());
        assertNull(result.getTopOrigin());
        assertFalse(result.isCrossOrigin());
    }

    @Test
    void testDeserialize_specialSymbolsInChallenge() throws Exception {
        final CollectedClientData result = CollectedClientDataDeserializer.deserialize("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTnpCaE9UY3labUV0TWpBd1lTMDBOVEZpTFdFM1lUY3RObVZqTVRNM01qTXdNV05oSmtFeEtrRXlNVU5hU3lwSmRHVjRkREhGdm14MUlIUmxlSFIxZHNTYjhKLU5sQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0=");

        assertEquals("""
                {"type":"webauthn.get","challenge":"NzBhOTcyZmEtMjAwYS00NTFiLWE3YTctNmVjMTM3MjMwMWNhJkExKkEyMUNaSypJdGV4dDHFvmx1IHRleHR1dsSb8J-NlA","origin":"http://localhost:8083","crossOrigin":false}
                """.strip(), result.getEncoded());
        assertEquals("webauthn.get", result.getType());
        assertEquals("70a972fa-200a-451b-a7a7-6ec1372301ca&A1*A21CZK*Itext1žlu textuvě\uD83C\uDF54", result.getChallenge());
        assertEquals("http://localhost:8083", result.getOrigin());
        assertNull(result.getTopOrigin());
        assertFalse(result.isCrossOrigin());
    }

}
