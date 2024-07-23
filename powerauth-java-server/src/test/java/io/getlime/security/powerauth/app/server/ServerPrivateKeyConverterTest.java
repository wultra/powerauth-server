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

import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link ServerPrivateKeyConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class ServerPrivateKeyConverterTest {

    private static final String SERVER_PRIVATE_KEY_PLAIN = "YAJ1A/QtTTB33R3Xnx3q7+QFuth6cRagtCMGTytV9VE=";

    private ServerPrivateKeyConverter serverPrivateKeyConverter;

    @Autowired
    public void setServerPrivateKeyConverter(ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(EncryptionMode.NO_ENCRYPTION, SERVER_PRIVATE_KEY_PLAIN);
        final String serverPrivateKeyActual = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, "test", "015286e0-e1c5-4ee1-8d1b-c6947cab0a56");

        assertEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKey serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes,"test", "015286e0-e1c5-4ee1-8d1b-c6947cab0a56");

        assertEquals(EncryptionMode.AES_HMAC, serverPrivateKeyEncrypted.getEncryptionMode());
        assertNotEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyEncrypted.getEncryptedData());

        final String serverPrivateKeyActual = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, "test", "015286e0-e1c5-4ee1-8d1b-c6947cab0a56");

        assertEquals(SERVER_PRIVATE_KEY_PLAIN, serverPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionDifferentUserFail() throws Exception {
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKey serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes, "test", "015286e0-e1c5-4ee1-8d1b-c6947cab0a56");

        assertThrows(GenericServiceException.class, () ->
                serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, "test2", "015286e0-e1c5-4ee1-8d1b-c6947cab0a56"));
    }

    @Test
    void testEncryptionAndDecryptionDifferentActivationFailServerPrivateKeyConverter() throws Exception {
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(SERVER_PRIVATE_KEY_PLAIN);
        final ServerPrivateKey serverPrivateKeyEncrypted = serverPrivateKeyConverter.toDBValue(serverPrivateKeyBytes, "test", "015286e0-e1c5-4ee1-8d1b-c6947cab0a56");

        assertThrows(GenericServiceException.class, () ->
                serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, "test", "115286e0-e1c5-4ee1-8d1b-c6947cab0a56"));
    }

}
