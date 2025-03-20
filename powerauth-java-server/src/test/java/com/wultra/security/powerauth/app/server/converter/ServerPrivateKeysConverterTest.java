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

import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeys;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link ServerPrivateKeysConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class ServerPrivateKeysConverterTest {

    private static final String ECDSA_PRIVATE_KEY = "APud3uNeR8GEImzD1J5xNQLOhykQp/YgajkL1nmvprn0xLsFjFVKPy9Gxbr2EBqBgw==";
    private static final String MLDSA_PRIVATE_KEY = "MDICAQAwCwYJYIZIAWUDBAMSBCDOgf2hERMl/CNLbwJCUlgQpB709Z0dxnmdAcs5k/PjvA==";

    private static final String SERVER_PRIVATE_KEYS_JSON = "{\"privateKeys\":{\"EC_P384_ML_L3\":{\"ECDSA\":\"" + ECDSA_PRIVATE_KEY + "\",\"MLDSA\":\"" + MLDSA_PRIVATE_KEY + "\"}}}";
    private static final String SERVER_PRIVATE_KEYS_ENCRYPTED = "8mYh1MO6WZUUwysE+a0ClyLaGgWtqjJ/NoBTeTL6+ftOTV2vEmvFjeqoDVSOursuvZFAZjKvCwSh0H9h4E5W0zujiUS57xO6NbQ7Vm8UFIUbBDg2Z+rdxU0Pa3EiEkeRQYbrI66KWmVqvtz0M9F1veh9yAxexu67Mo/02eBIRuw89DuAMBO9FN8YEm5a/NvFb4olasJwAKjsCyAaX8k+TcLfj0sa8wZYUWPtT6SdKcGF6V2O0euOKNbB2KyyV5Cz4OVZRj6AimlPaFLnsG8fjary8013Q+fkvRvxgI8dDRM=";

    private static final String USER_ID = "test";

    private static final String ACTIVATION_ID = "015286e0-e1c5-4ee1-8d1b-c6947cab0a56";

    @Autowired
    private ServerPrivateKeysConverter privateKeysConverter;

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new PqcDsaKeyConvertor();

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final PrivateKeyRegistry keyRegistry = new PrivateKeyRegistry();
        final PrivateKey ecdsaPrivateKey = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        keyRegistry.storePrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.ECDSA, ecdsaPrivateKey);
        final PrivateKey mlDsaPrivateKey = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        keyRegistry.storePrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.MLDSA, mlDsaPrivateKey);
        final byte[] keyRegistryBytes = privateKeysConverter.serialize(keyRegistry);
        final String keyRegistryBase64 = Base64.getEncoder().encodeToString(keyRegistryBytes);
        final PrivateKeys privateKeysEncrypted = new PrivateKeys(EncryptionMode.NO_ENCRYPTION, keyRegistryBase64);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, ACTIVATION_ID);
        final Optional<PrivateKey> ecdsaPrivateKeyActual = serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.ECDSA);
        assertFalse(ecdsaPrivateKeyActual.isEmpty());
        final byte[] ecdsaPrivateKeyActualBytes = KEY_CONVERTOR_EC.convertPrivateKeyToBytes(ecdsaPrivateKeyActual.get());
        final Optional<PrivateKey> mlDsaPrivateKeyActual = serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.MLDSA);
        assertFalse(mlDsaPrivateKeyActual.isEmpty());
        final byte[] mlDsaPrivateKeyActualBytes = mlDsaPrivateKeyActual.get().getEncoded();
        assertEquals(ECDSA_PRIVATE_KEY, Base64.getEncoder().encodeToString(ecdsaPrivateKeyActualBytes));
        assertEquals(MLDSA_PRIVATE_KEY, Base64.getEncoder().encodeToString(mlDsaPrivateKeyActualBytes));
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        final byte[] serverPrivateKeysBytes = SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeys privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, USER_ID, ACTIVATION_ID);
        assertEquals(EncryptionMode.AES_HMAC, privateKeysEncrypted.encryptionMode());
        assertNotEquals(SERVER_PRIVATE_KEYS_JSON, privateKeysEncrypted.privateKeysBase64());
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, ACTIVATION_ID);
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.ECDSA).get());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.MLDSA).get());
    }

    @Test
    void testFromDbValueEncryption() throws Exception {
        final PrivateKeys privateKeysEncrypted = new PrivateKeys(EncryptionMode.AES_HMAC, SERVER_PRIVATE_KEYS_ENCRYPTED);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, ACTIVATION_ID);
        assertArrayEquals(SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8), privateKeysConverter.serialize(serverPrivateKeysActual));
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.ECDSA).get());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.MLDSA).get());
    }

    @Test
    void testEncryptionAndDecryptionDifferentUserFail() throws Exception {
        final byte[] serverPrivateKeysBytes = SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeys privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, privateKeysEncrypted.encryptionMode());
        assertThrows(GenericServiceException.class, () ->
            privateKeysConverter.fromDBValue(privateKeysEncrypted, "test2", ACTIVATION_ID));
    }

    @Test
    void testEncryptionAndDecryptionDifferentActivationFailServerPrivateKeysConverter() throws Exception {
        final byte[] serverPrivateKeysBytes = SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeys privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, privateKeysEncrypted.encryptionMode());

        try {
            final PrivateKeyRegistry decryptedPrivateKeys = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, "115286e0-e1c5-4ee1-8d1b-c6947cab0a56");
            assertFalse(Arrays.equals(SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8), privateKeysConverter.serialize(decryptedPrivateKeys)));
        } catch (GenericServiceException ex) {
            assertEquals("Generic cryptography error occurred.", ex.getMessage());
        }
    }

}
