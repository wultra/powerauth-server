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

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.converter.v3.RecoveryPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPrivateKey;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for encryption and decryption of recovery private keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ExtendWith(SpringExtension.class)
public class RecoveryPrivateKeyConverterTest {

    private static final String RECOVERY_PRIVATE_KEY_PLAIN = "ALwHHv90Ixaor+8CkBThDQP/8UUm59Bvdod5u7z97zGm";

    private RecoveryPrivateKeyConverter recoveryPrivateKeyConverter;

    @Autowired
    public void setRecoveryPrivateKeyConverter(RecoveryPrivateKeyConverter recoveryPrivateKeyConverter) {
        this.recoveryPrivateKeyConverter = recoveryPrivateKeyConverter;
    }

    @Test
    public void testFromDbValueNoEncryption() throws Exception {
        final RecoveryPrivateKey recoveryPrivateKeyEncrypted = new RecoveryPrivateKey(EncryptionMode.NO_ENCRYPTION, RECOVERY_PRIVATE_KEY_PLAIN);
        String recoveryPrivateKeyActual = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, 1);
        assertEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    public void testEncryptionAndDecryptionSuccess() throws Exception {
        byte[] recoveryPrivateKeyBytes = BaseEncoding.base64().decode(RECOVERY_PRIVATE_KEY_PLAIN);
        RecoveryPrivateKey recoveryPrivateKeyEncrypted = recoveryPrivateKeyConverter.toDBValue(recoveryPrivateKeyBytes,1);
        String recoveryPrivateKeyActual = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, 1);
        assertEquals(RECOVERY_PRIVATE_KEY_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    public void testEncryptionAndDecryptionDifferentApplicationFail() {
        assertThrows(GenericServiceException.class, ()-> {
            byte[] recoveryPrivateKeyBytes = BaseEncoding.base64().decode(RECOVERY_PRIVATE_KEY_PLAIN);
            RecoveryPrivateKey recoveryPrivateKeyEncrypted = recoveryPrivateKeyConverter.toDBValue(recoveryPrivateKeyBytes, 1);
            recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, 2);
        });
    }

}
