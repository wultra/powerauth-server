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

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
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
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link MasterPrivateKeysConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class MasterPrivateKeysConverterTest {

    private static final String ECDSA_PRIVATE_KEY = "APEKs9JvvLiNMOYoP9AB/ysrqa3NvTjGz5zdEZu0j2MjKxMyKKoTWtOtUHt6AfBAZg==";
    private static final String MLDSA_PRIVATE_KEY = "MDICAQAwCwYJYIZIAWUDBAMSBCDjgy6AIFJt1eRaBN8FVmwaSQTtyMnFzcRJ5tCh8M+6SA==";

    private static final String MASTER_PRIVATE_KEYS_JSON = "{\"privateKeys\":{\"EC_P384_ML_L3\":{\"ECDSA\":\"" + ECDSA_PRIVATE_KEY + "\",\"MLDSA\":\"" + MLDSA_PRIVATE_KEY + "\"}}}";
    private static final String MASTER_PRIVATE_KEYS_ENCRYPTED = "j535AIE/smRhCbeZF8Xw40tim+7MbvWB8U6ITNIInYyHjN/Jq8blsaVfDc4CP5RPnfzzQHqJnqTqgd6qcQvJQFLIG8J6dwfx5RhY28vB/uSzMwAV8v1kF27I7yelVmIw6lFFFo0ctvbluVYelDFxdqZ3ng1DiJ6DuGLbPequSMbf1YjjLLoi8FbwUIKMLqqZeB8HqxEbdsA98DIYomAVXU9UsEOIUr4lOq2YnaCJIsrrFBlYXZyzFj01KaNvm94qLLNlgRe8Vbu5/5ro8/fNTOFID6BfuwKR7Am7R3Y7tow=";

    private static final String APPLICATION_ID = "test";

    @Autowired
    private MasterPrivateKeysConverter privateKeysConverter;

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
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, APPLICATION_ID);
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
        final byte[] serverPrivateKeysBytes = MASTER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeys privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, APPLICATION_ID);
        assertEquals(EncryptionMode.AES_HMAC, privateKeysEncrypted.encryptionMode());
        assertNotEquals(MASTER_PRIVATE_KEYS_JSON, privateKeysEncrypted.privateKeysBase64());
        System.out.println(privateKeysEncrypted.privateKeysBase64());
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, APPLICATION_ID);
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.ECDSA).get());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.MLDSA).get());
    }

    @Test
    void testFromDbValueEncryption() throws Exception {
        final PrivateKeys privateKeysEncrypted = new PrivateKeys(EncryptionMode.AES_HMAC, MASTER_PRIVATE_KEYS_ENCRYPTED);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, APPLICATION_ID);
        assertArrayEquals(MASTER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8), privateKeysConverter.serialize(serverPrivateKeysActual));
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.ECDSA).get());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(SharedSecretAlgorithm.EC_P384_ML_L3, KeyType.MLDSA).get());
    }

    @Test
    void testEncryptionAndDecryptionDifferentApplicationIdFail() throws Exception {
        final byte[] serverPrivateKeysBytes = MASTER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeys privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, APPLICATION_ID);

        assertEquals(EncryptionMode.AES_HMAC, privateKeysEncrypted.encryptionMode());
        assertThrows(GenericServiceException.class, () ->
            privateKeysConverter.fromDBValue(privateKeysEncrypted, "test2"));
    }

}
