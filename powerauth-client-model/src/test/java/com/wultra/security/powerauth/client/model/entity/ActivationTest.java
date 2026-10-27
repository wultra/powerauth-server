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
 *
 */
package com.wultra.security.powerauth.client.model.entity;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of the device public keys representation of {@link Activation}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class ActivationTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @Test
    void serializationOmitsDevicePublicKeysWhenEmpty() {
        final Activation activation = new Activation();
        activation.setActivationId("id");

        final JsonNode json = MAPPER.readTree(MAPPER.writeValueAsString(activation));

        assertFalse(json.has("devicePublicKeys"));
        assertEquals("id", json.get("activationId").asString());
    }

    @Test
    void serializationContainsDevicePublicKeysByType() {
        final Activation activation = new Activation();
        activation.setDevicePublicKeys(new LinkedHashMap<>(Map.of("ECDSA_P384", "ecKey", "MLDSA_65", "mlKey")));

        final JsonNode keys = MAPPER.readTree(MAPPER.writeValueAsString(activation)).get("devicePublicKeys");

        assertNotNull(keys);
        assertEquals(2, keys.size());
        assertEquals("ecKey", keys.get("ECDSA_P384").asString());
        assertEquals("mlKey", keys.get("MLDSA_65").asString());
    }

    @Test
    void deserializationWithoutDevicePublicKeysYieldsEmptyMap() {
        final Activation activation = MAPPER.readValue("{\"activationId\":\"id\"}", Activation.class);

        assertNotNull(activation.getDevicePublicKeys());
        assertTrue(activation.getDevicePublicKeys().isEmpty());
    }

    @Test
    void toStringDoesNotExposeDevicePublicKeys() {
        final Activation activation = new Activation();
        activation.setDevicePublicKeys(new LinkedHashMap<>(Map.of("ECDSA_P384", "secretLookingKeyMaterial")));

        assertFalse(activation.toString().contains("secretLookingKeyMaterial"));
    }

}
