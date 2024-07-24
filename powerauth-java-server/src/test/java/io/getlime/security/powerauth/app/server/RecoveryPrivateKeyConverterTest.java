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

    private RecoveryPrivateKeyConverter recoveryPrivateKeyConverter;

    @Autowired
    public void setRecoveryPrivateKeyConverter(RecoveryPrivateKeyConverter recoveryPrivateKeyConverter) {
        this.recoveryPrivateKeyConverter = recoveryPrivateKeyConverter;
    }

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = new RecoveryPrivateKey(EncryptionMode.NO_ENCRYPTION, RECOVERY_PRIVATE_KEY_PLAIN);
        final String recoveryPrivateKeyActual = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, 1);

        assertEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        final byte[] recoveryPrivateKeyBytes = Base64.getDecoder().decode(RECOVERY_PRIVATE_KEY_PLAIN);
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = recoveryPrivateKeyConverter.toDBValue(recoveryPrivateKeyBytes, 1);

        assertEquals(EncryptionMode.AES_HMAC, recoveryPrivateKeyEncrypted.getEncryptionMode());
        assertNotEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyEncrypted.getEncryptedData());

        final String recoveryPrivateKeyActual = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, 1);
        assertEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionDifferentApplicationFail() throws Exception {
        final byte[] recoveryPrivateKeyBytes = Base64.getDecoder().decode(RECOVERY_PRIVATE_KEY_PLAIN);
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = recoveryPrivateKeyConverter.toDBValue(recoveryPrivateKeyBytes, 1);

        assertThrows(GenericServiceException.class, () ->
                recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, 2));
    }

}
