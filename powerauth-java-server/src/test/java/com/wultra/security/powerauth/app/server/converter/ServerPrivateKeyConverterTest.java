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

import static com.wultra.security.powerauth.app.server.util.AssertionUtils.assertThrowsOrNotEqual;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.wultra.security.powerauth.app.server.database.model.ServerPrivateKeyRecord;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;

/**
 * Tests for {@link ServerPrivateKeyConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class ServerPrivateKeyConverterTest {

    private static final String SERVER_PRIVATE_KEY_PLAIN = "YAJ1A/QtTTB33R3Xnx3q7+QFuth6cRagtCMGTytV9VE=";

    private static final String SERVER_PRIVATE_KEY_AES_HMAC_ENCRYPTED = "dzAdH8ZcOwbOsbBKIy86WpT6nFHTnKQQ/ifbk+z99LrToahYrDOyqVGMdw7eiELf+qrS8rjZFoz9oBcqGM35hQ==";
    private static final String SERVER_PRIVATE_KEY_AEAD_KMAC_ENCRYPTED = "8pUlMiEtNYR69WlqQcOWHVRcqr6LUSMdEbhdVO/0jDksZnjBCp2jZivYdtyMtnyzCbJZFZjOSeZKmVzpDWPtiGDnATZDYIMCPOYwQg==";

    private static final String USER_ID = "test";

    private static final String ACTIVATION_ID = "015286e0-e1c5-4ee1-8d1b-c6947cab0a56";

    @Autowired
    private ServerPrivateKeyConverter serverPrivateKeyConverter;

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final ServerPrivateKeyRecord serverPrivateKeyEncrypted = new ServerPrivateKeyRecord(EncryptionMode.NO_ENCRYPTION, SERVER_PRIVATE_KEY_PLAIN);
        final String serverPrivateKeyActual = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, ACTIVATION_ID);

        assertEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKeyRecord serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes, USER_ID, ACTIVATION_ID);
        assertEquals(EncryptionMode.AEAD_KMAC, serverPrivateKeyEncrypted.encryptionMode());
        assertNotEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyEncrypted.serverPrivateKeyBase64());

        final String serverPrivateKeyActual = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, ACTIVATION_ID);
        assertEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyActual);
    }

    @Test
    void testFromDbValueEncryptionAesHmac() throws Exception {
        final ServerPrivateKeyRecord serverPrivateKeyEncrypted = new ServerPrivateKeyRecord(EncryptionMode.AES_HMAC, SERVER_PRIVATE_KEY_AES_HMAC_ENCRYPTED);
        final String result = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, ACTIVATION_ID);
        assertEquals(SERVER_PRIVATE_KEY_PLAIN, result);
    }

    @Test
    void testFromDbValueEncryptionAeadKmac() throws Exception {
        final ServerPrivateKeyRecord serverPrivateKeyEncrypted = new ServerPrivateKeyRecord(EncryptionMode.AEAD_KMAC, SERVER_PRIVATE_KEY_AEAD_KMAC_ENCRYPTED);
        final String result = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, ACTIVATION_ID);
        assertEquals(SERVER_PRIVATE_KEY_PLAIN, result);
    }


    @Test
    void testEncryptionAndDecryptionDifferentUserFail() throws Exception {
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKeyRecord serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionMode.AEAD_KMAC, serverPrivateKeyEncrypted.encryptionMode());
        assertThrowsOrNotEqual(GenericServiceException.class,
                () -> serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, "test2", ACTIVATION_ID),
                serverPrivateKeyBytes);
    }

    @Test
    void testEncryptionAndDecryptionDifferentActivationFailServerPrivateKeyConverter() throws Exception {
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKeyRecord serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionMode.AEAD_KMAC, serverPrivateKeyEncrypted.encryptionMode());

        assertThrowsOrNotEqual(GenericServiceException.class,
                () -> serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, "115286e0-e1c5-4ee1-8d1b-c6947cab0a56"),
                serverPrivateKeyBytes);
    }

}
