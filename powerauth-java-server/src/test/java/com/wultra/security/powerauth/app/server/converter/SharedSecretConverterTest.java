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

import com.wultra.security.powerauth.app.server.database.model.SharedSecret;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link com.wultra.security.powerauth.app.server.converter.SharedSecretConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class SharedSecretConverterTest {

    private static final String SHARED_SECRET_BASE64 = "G9Pa9bVMtZMTH04QQ+69yvaLGqeKFFan3bsfluA10qiYbc/kEsJK0oFINkyc19MMo1mr53BnrSpZ3IZre0MZVpxhq15cjDHJJ6lk/Q3dO8w=";

    private static final String SHARED_SECRET_ENCRYPTED = "KzfTnYq9toTVkmJleGrx03u2XZX1ky9CBOSU/hP/TKOoZpwSawcIzzvhevYfVTRrw58CtumNsLPkEn0NNXDrUc1PdVpbF0FEo1cTVNvItoWe5LRQYEvMddBrQ/W/bpX0MlVWjTVQj2mZDhlaC7DHIQ==";

    private static final String USER_ID = "test";

    private static final String ACTIVATION_ID = "015286e0-e1c5-4ee1-8d1b-c6947cab0a56";

    @Autowired
    private SharedSecretConverter sharedSecretConverter;

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final SharedSecret sharedSecret = new SharedSecret(EncryptionMode.NO_ENCRYPTION, SHARED_SECRET_BASE64);
        final String sharedSecretActual = sharedSecretConverter.fromDBValue(sharedSecret, USER_ID, ACTIVATION_ID);

        assertEquals(SHARED_SECRET_BASE64, sharedSecretActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecret sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, USER_ID, ACTIVATION_ID);
        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());
        assertNotEquals(SHARED_SECRET_BASE64, sharedSecretEncrypted.sharedSecretBase64());

        final String sharedSecretActual = sharedSecretConverter.fromDBValue(sharedSecretEncrypted, USER_ID, ACTIVATION_ID);
        assertEquals(SHARED_SECRET_BASE64, sharedSecretActual);
    }

    @Test
    void testFromDbValueEncryption() throws Exception {
        final SharedSecret sharedSecretEncrypted = new SharedSecret(EncryptionMode.AES_HMAC, SHARED_SECRET_ENCRYPTED);
        final String result = sharedSecretConverter.fromDBValue(sharedSecretEncrypted, USER_ID, ACTIVATION_ID);
        assertEquals(SHARED_SECRET_BASE64, result);
    }

    @Test
    void testEncryptionAndDecryptionDifferentUserFail() throws Exception {
        final byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecret sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());
        assertThrows(GenericServiceException.class, () ->
                sharedSecretConverter.fromDBValue(sharedSecretEncrypted, "test2", ACTIVATION_ID));
    }

    @Test
    void testEncryptionAndDecryptionDifferentActivationFailServerSharedSecretConverter() throws Exception {
        final byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecret sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> sharedSecretConverter.fromDBValue(sharedSecretEncrypted, USER_ID, "115286e0-e1c5-4ee1-8d1b-c6947cab0a56"));
        assertEquals("Generic cryptography error occurred.", exception.getMessage());
    }

}
