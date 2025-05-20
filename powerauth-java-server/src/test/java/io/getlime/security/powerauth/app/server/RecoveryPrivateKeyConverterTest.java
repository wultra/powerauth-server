/*
 * PowerAuth Recovery and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.converter.RecoveryPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link RecoveryPrivateKeyConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class RecoveryPrivateKeyConverterTest {

    private static final String RECOVERY_PRIVATE_KEY_PLAIN = "ALwHHv90Ixaor+8CkBThDQP/8UUm59Bvdod5u7z97zGm";

    private static final String RECOVERY_PRIVATE_KEY_ENCRYPTED = "/hBWhJdca6IeZcNzLRSiLkzYQgTwa/AlCHWaUzXXFdu4R4AmWk2WxMWFBclXa/jWAznEOC3irjwLbjP8buFrLQ==";

    private static final int APPLICATION_ID = 1;

    @Autowired
    private RecoveryPrivateKeyConverter recoveryPrivateKeyConverter;

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = new RecoveryPrivateKey(EncryptionMode.NO_ENCRYPTION, RECOVERY_PRIVATE_KEY_PLAIN);
        final String recoveryPrivateKeyActual = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, APPLICATION_ID);

        assertEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        final byte[] recoveryPrivateKeyBytes = Base64.getDecoder().decode(RECOVERY_PRIVATE_KEY_PLAIN);
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = recoveryPrivateKeyConverter.toDBValue(recoveryPrivateKeyBytes, APPLICATION_ID);
        assertEquals(EncryptionMode.AES_HMAC, recoveryPrivateKeyEncrypted.encryptionMode());
        assertNotEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyEncrypted.recoveryPrivateKeyBase64());

        final String recoveryPrivateKeyActual = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, APPLICATION_ID);

        assertEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    void testFromDbValueEncryption() throws Exception {
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = new RecoveryPrivateKey(EncryptionMode.AES_HMAC, RECOVERY_PRIVATE_KEY_ENCRYPTED);
        final String recoveryPrivateKeyActual = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, APPLICATION_ID);

        assertEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionDifferentApplicationFail() throws Exception {
        final byte[] recoveryPrivateKeyBytes = Base64.getDecoder().decode(RECOVERY_PRIVATE_KEY_PLAIN);
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = recoveryPrivateKeyConverter.toDBValue(recoveryPrivateKeyBytes, APPLICATION_ID);

        assertThrows(GenericServiceException.class, () ->
            recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, 2));
    }

}
