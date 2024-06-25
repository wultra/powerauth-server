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

}
