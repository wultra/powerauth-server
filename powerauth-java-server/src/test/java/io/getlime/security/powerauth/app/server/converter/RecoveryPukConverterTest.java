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
package io.getlime.security.powerauth.app.server.converter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import io.getlime.security.powerauth.app.server.database.model.RecoveryPuk;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;

/**
 * Test for {@link RecoveryPukConverter}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class RecoveryPukConverterTest {

    private static final String PUK_PLAIN = "1234";

    private static final String PUK_ENCRYPTED = "dOYc+eyTERSmYhtLviphrJbNfQndB844bWdZIgIM4Fs=";

    private static final int APPLICATION_ID = 1;
    private static final String USER_ID = "joe";
    private static final String RECOVERY_CODE = "1111";
    private static final long PUK_INDEX = 42L;

    @Autowired
    private RecoveryPukConverter tested;

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final RecoveryPuk recoveryPuk = new RecoveryPuk(EncryptionMode.NO_ENCRYPTION, PUK_PLAIN);
        final String recoveryPrivateKeyActual = tested.fromDBValue(recoveryPuk, APPLICATION_ID, USER_ID, RECOVERY_CODE, PUK_INDEX);

        assertEquals(PUK_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        final RecoveryPuk recoveryPukEncrypted = tested.toDBValue(PUK_PLAIN, APPLICATION_ID, USER_ID, RECOVERY_CODE, PUK_INDEX);
        assertEquals(EncryptionMode.AES_HMAC, recoveryPukEncrypted.encryptionMode());
        assertNotEquals(PUK_PLAIN, recoveryPukEncrypted.pukHash());

        final String recoveryPukActual = tested.fromDBValue(recoveryPukEncrypted, APPLICATION_ID, USER_ID, RECOVERY_CODE, PUK_INDEX);

        assertEquals(PUK_PLAIN, recoveryPukActual);
    }

    @Test
    void testFromDbValueEncryption() throws Exception {
        final RecoveryPuk recoveryPuk = new RecoveryPuk(EncryptionMode.AES_HMAC, PUK_ENCRYPTED);
        final String recoveryPrivateKeyActual = tested.fromDBValue(recoveryPuk, APPLICATION_ID, USER_ID, RECOVERY_CODE, PUK_INDEX);

        assertEquals(PUK_PLAIN, recoveryPrivateKeyActual);
    }

    @Test
    void testEncryptionAndDecryptionDifferentDerivedKeyFail() throws Exception {
        final RecoveryPuk recoveryPukEncrypted = tested.toDBValue(PUK_PLAIN, APPLICATION_ID, USER_ID, RECOVERY_CODE, PUK_INDEX);

        assertThrows(GenericServiceException.class, () ->
            tested.fromDBValue(recoveryPukEncrypted, -1, USER_ID, RECOVERY_CODE, PUK_INDEX));
        assertThrows(GenericServiceException.class, () ->
            tested.fromDBValue(recoveryPukEncrypted, APPLICATION_ID, "error", RECOVERY_CODE, PUK_INDEX));
        assertThrows(GenericServiceException.class, () ->
            tested.fromDBValue(recoveryPukEncrypted, APPLICATION_ID, USER_ID, "error", PUK_INDEX));
        assertThrows(GenericServiceException.class, () ->
            tested.fromDBValue(recoveryPukEncrypted, APPLICATION_ID, USER_ID, RECOVERY_CODE, -1));
    }

}
