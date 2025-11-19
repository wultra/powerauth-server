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

import com.wultra.security.powerauth.app.server.database.model.SharedSecretRecord;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static com.wultra.security.powerauth.app.server.util.AssertionUtils.assertThrowsOrNotEqual;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TemporarySharedSecretConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class TemporarySharedSecretConverterTest {

    private static final String SHARED_SECRET_BASE64 = "G9Pa9bVMtZMTH04QQ+69yvaLGqeKFFan3bsfluA10qiYbc/kEsJK0oFINkyc19MMo1mr53BnrSpZ3IZre0MZVpxhq15cjDHJJ6lk/Q3dO8w=";

    private static final String SHARED_SECRET_ENCRYPTED = "NRyCX0zwu5Idd5i2mwsvs/RL9uVnZE7sVyvurjeNcIf6ZwhYsl/TbuLrHFL03FicXjhv17n729jHIh341zi9iOJcr3RDKBo3jWGC6TxiPBvU7OlH+Sd3KfcsZ4QSO68OJQvhD4eSN9uhXjdajn+x6w==";

    private static final String KEY_ID = "c2079c74-9650-43f9-93d3-5f5af7181ecd";

    private static final String APP_KEY = "Z19gyYaW5kb521fYWN0aXZ==";

    private static final String ACTIVATION_ID = "015286e0-e1c5-4ee1-8d1b-c6947cab0a56";

    @Autowired
    private TemporarySharedSecretConverter sharedSecretConverter;

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final SharedSecretRecord sharedSecret = new SharedSecretRecord(EncryptionMode.NO_ENCRYPTION, SHARED_SECRET_BASE64);
        final String sharedSecretActual = sharedSecretConverter.fromDBValue(sharedSecret, KEY_ID, APP_KEY, ACTIVATION_ID);

        assertEquals(SHARED_SECRET_BASE64, sharedSecretActual);
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecretRecord sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, KEY_ID, APP_KEY, ACTIVATION_ID);
        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());
        assertNotEquals(SHARED_SECRET_BASE64, sharedSecretEncrypted.sharedSecretBase64());

        final String sharedSecretActual = sharedSecretConverter.fromDBValue(sharedSecretEncrypted, KEY_ID, APP_KEY, ACTIVATION_ID);
        assertEquals(SHARED_SECRET_BASE64, sharedSecretActual);
    }

    @Test
    void testFromDbValueEncryption() throws Exception {
        final SharedSecretRecord sharedSecretEncrypted = new SharedSecretRecord(EncryptionMode.AES_HMAC, SHARED_SECRET_ENCRYPTED);
        final String result = sharedSecretConverter.fromDBValue(sharedSecretEncrypted, KEY_ID, APP_KEY, ACTIVATION_ID);
        assertEquals(SHARED_SECRET_BASE64, result);
    }

    @Test
    void testEncryptionAndDecryptionDifferentKeyIdFail() throws Exception {
        final byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecretRecord sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, KEY_ID, APP_KEY, ACTIVATION_ID);
        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());
        assertThrowsOrNotEqual(GenericServiceException.class,
                () -> sharedSecretConverter.fromDBValue(sharedSecretEncrypted, "1839c333-f61a-4be0-8d34-75b7cb79ab76", APP_KEY, ACTIVATION_ID),
                sharedSecretBytes);
    }

    @Test
    void testEncryptionAndDecryptionDifferentAppKeyFail() throws Exception {
        final byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecretRecord sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, KEY_ID, APP_KEY, ACTIVATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());
        assertThrowsOrNotEqual(GenericServiceException.class,
                () -> sharedSecretConverter.fromDBValue(sharedSecretEncrypted, KEY_ID, "UNfS0VZX3JhbmRvbQ==", ACTIVATION_ID),
                sharedSecretBytes);
    }

    @Test
    void testEncryptionAndDecryptionDifferentActivationIdFail() throws Exception {
        final byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecretRecord sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, KEY_ID, APP_KEY, ACTIVATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());
        assertThrowsOrNotEqual(GenericServiceException.class,
                () -> sharedSecretConverter.fromDBValue(sharedSecretEncrypted, KEY_ID, APP_KEY, "01e9deb4-a0e0-4204-b8a6-925e76b7b3d3"),
                sharedSecretBytes);
    }

    @Test
    void testEncryptionAndDecryptionNoActivationIdFail() throws Exception {
        final byte[] sharedSecretBytes = Base64.getDecoder().decode(SHARED_SECRET_BASE64);
        final SharedSecretRecord sharedSecretEncrypted = sharedSecretConverter.toDBValue(sharedSecretBytes, KEY_ID, APP_KEY, ACTIVATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, sharedSecretEncrypted.encryptionMode());
        assertThrowsOrNotEqual(GenericServiceException.class,
                () -> sharedSecretConverter.fromDBValue(sharedSecretEncrypted, KEY_ID, APP_KEY, null),
                sharedSecretBytes);
    }

}
