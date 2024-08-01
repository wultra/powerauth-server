/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;

/**
 * Tests for {@link ServerPrivateKeyConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class ServerPrivateKeyConverterTest {

    private static final String SERVER_PRIVATE_KEY_PLAIN = "YAJ1A/QtTTB33R3Xnx3q7+QFuth6cRagtCMGTytV9VE=";

    private static final String SERVER_PRIVATE_KEY_ENCRYPTED = "dzAdH8ZcOwbOsbBKIy86WpT6nFHTnKQQ/ifbk+z99LrToahYrDOyqVGMdw7eiELf+qrS8rjZFoz9oBcqGM35hQ==";

    private static final String USER_ID = "test";

    private static final String ACTIVATION_ID = "015286e0-e1c5-4ee1-8d1b-c6947cab0a56";

    @Autowired
    private ServerPrivateKeyConverter serverPrivateKeyConverter;

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(EncryptionMode.NO_ENCRYPTION, SERVER_PRIVATE_KEY_PLAIN);
        final String serverPrivateKeyActual = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, ACTIVATION_ID);

        assertEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKey serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes,USER_ID, ACTIVATION_ID);
        assertEquals(EncryptionMode.AES_HMAC, serverPrivateKeyEncrypted.encryptionMode());
        assertNotEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyEncrypted.serverPrivateKeyBase64());

        final String serverPrivateKeyActual = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, ACTIVATION_ID);
        assertEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyActual);
    }

    @Test
    void testFromDbValueEncryption() throws Exception {
        final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(EncryptionMode.AES_HMAC, SERVER_PRIVATE_KEY_ENCRYPTED);
        final String result = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, ACTIVATION_ID);
        assertEquals(SERVER_PRIVATE_KEY_PLAIN, result);
    }

    @Test
    void testEncryptionAndDecryptionDifferentUserFail() throws Exception {
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKey serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes, USER_ID, ACTIVATION_ID);

        assertThrows(GenericServiceException.class, () ->
            serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, "test2", ACTIVATION_ID));
    }

    @Test
    void testEncryptionAndDecryptionDifferentActivationFailServerPrivateKeyConverter() throws Exception {
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKey serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes, USER_ID, ACTIVATION_ID);

        assertThrows(GenericServiceException.class, () ->
            serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, USER_ID, "115286e0-e1c5-4ee1-8d1b-c6947cab0a56"));
    }

}
