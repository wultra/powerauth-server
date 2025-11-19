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
import com.wultra.security.powerauth.app.server.database.model.PrivateKeysRecord;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
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
 * Tests for {@link ServerPrivateKeysConverter}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class ServerPrivateKeysConverterTest {

    private static final String ECDSA_PRIVATE_KEY = "APud3uNeR8GEImzD1J5xNQLOhykQp/YgajkL1nmvprn0xLsFjFVKPy9Gxbr2EBqBgw==";
    private static final String MLDSA_PRIVATE_KEY = "MDICAQAwCwYJYIZIAWUDBAMSBCDOgf2hERMl/CNLbwJCUlgQpB709Z0dxnmdAcs5k/PjvA==";

    private static final String SERVER_PRIVATE_KEYS_JSON = "{\"privateKeys\":{\"ECDSA_P384\":\"" + ECDSA_PRIVATE_KEY + "\",\"MLDSA_65\":\"" + MLDSA_PRIVATE_KEY + "\"}}";
    private static final String SERVER_PRIVATE_KEYS_AES_HMAC_ENCRYPTED = "RzylCQURjkitPt93yycj0CzAjlgdZ7JmlvWwWNmtzKbuYEPNsZ3v/XQv+UyfabT4vaHKLy+UYkq1xoXbWOP1rhStZodSG84XE91tv6Tw4X94yCcXW69mI+2gchuSEGfvIfPxg3AO/vL9YOVwmaHgQOiMoURldRSR/gMjyvHLoA2yY0qecSKXYKA9Xh2TGHYtMxDQOdIVyBF1Azi7vJZIdDa0HNs5Wxep6+rmUH/VfyvTEcf/KIb+LSN+I9U/OjW1zOZA+kTfI6PKHACLMcnMew==";
    private static final String SERVER_PRIVATE_KEYS_AEAD_KMAC_ENCRYPTED = "7mymZRjjwzBE5NManafOzhsfMzaKhbcAkE6xGAoDaONQGmDctJuxdK7JMGgQvJ194XXjUuPM95CczBXu3Y1Rh19MhZ2rkF3xLXzBVupcwPkoHphg+tacpAsZW9Ar+HHd6anwElS5GirkLvtqLqZ4rrxvgfYX6sZMdS/fDFEkL4dfXMlEmvSC255J9B55bsgm5/6K9VqfoNDip6VTc5jH0DTlnwDk2RxfafupVCthCda/p78K/uHghyLgz3D7+wbxHUXTQ4roDbhQNwgOQNF/mx5+fonC/CYXo3CIRkl5XVun3nbUQIlU";

    private static final String USER_ID = "test";

    private static final String ACTIVATION_ID = "015286e0-e1c5-4ee1-8d1b-c6947cab0a56";

    @Autowired
    private ServerPrivateKeysConverter privateKeysConverter;

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    @Test
    void testFromDbValueNoEncryption() throws Exception {
        final PrivateKeyRegistry keyRegistry = new PrivateKeyRegistry();
        final PrivateKey ecdsaPrivateKey = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        keyRegistry.storePrivateKey(KeyType.ECDSA_P384, ecdsaPrivateKey);
        final PrivateKey mlDsaPrivateKey = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        keyRegistry.storePrivateKey(KeyType.MLDSA_65, mlDsaPrivateKey);
        final byte[] keyRegistryBytes = privateKeysConverter.serialize(keyRegistry);
        final String keyRegistryBase64 = Base64.getEncoder().encodeToString(keyRegistryBytes);
        final PrivateKeysRecord privateKeysEncrypted = new PrivateKeysRecord(EncryptionAlgorithm.NO_ENCRYPTION, keyRegistryBase64);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, ACTIVATION_ID);
        final Optional<PrivateKey> ecdsaPrivateKeyActual = serverPrivateKeysActual.getPrivateKey(KeyType.ECDSA_P384);
        assertFalse(ecdsaPrivateKeyActual.isEmpty());
        final byte[] ecdsaPrivateKeyActualBytes = KEY_CONVERTOR_EC.convertPrivateKeyToBytes(ecdsaPrivateKeyActual.get());
        final Optional<PrivateKey> mlDsaPrivateKeyActual = serverPrivateKeysActual.getPrivateKey(KeyType.MLDSA_65);
        assertFalse(mlDsaPrivateKeyActual.isEmpty());
        final byte[] mlDsaPrivateKeyActualBytes = KEY_CONVERTOR_PQC_DSA.convertPrivateKeyToBytes(mlDsaPrivateKeyActual.get());
        assertEquals(ECDSA_PRIVATE_KEY, Base64.getEncoder().encodeToString(ecdsaPrivateKeyActualBytes));
        assertEquals(MLDSA_PRIVATE_KEY, Base64.getEncoder().encodeToString(mlDsaPrivateKeyActualBytes));
    }

    @Test
    void testEncryptionAndDecryptionSuccess() throws Exception {
        final byte[] serverPrivateKeysBytes = SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeysRecord privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, USER_ID, ACTIVATION_ID);
        assertEquals(EncryptionAlgorithm.AEAD_KMAC, privateKeysEncrypted.encryptionAlgorithm());
        assertNotEquals(SERVER_PRIVATE_KEYS_JSON, privateKeysEncrypted.privateKeysBase64());
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, ACTIVATION_ID);
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.ECDSA_P384).orElseThrow());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.MLDSA_65).orElseThrow());
    }

    @Test
    void testFromDbValueEncryptionAesHmac() throws Exception {
        final PrivateKeysRecord privateKeysEncrypted = new PrivateKeysRecord(EncryptionAlgorithm.AES_HMAC, SERVER_PRIVATE_KEYS_AES_HMAC_ENCRYPTED);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, ACTIVATION_ID);
        assertArrayEquals(SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8), privateKeysConverter.serialize(serverPrivateKeysActual));
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.ECDSA_P384).orElseThrow());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.MLDSA_65).orElseThrow());
    }

    @Test
    void testFromDbValueEncryptionAeadKmac() throws Exception {
        final PrivateKeysRecord privateKeysEncrypted = new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, SERVER_PRIVATE_KEYS_AEAD_KMAC_ENCRYPTED);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, ACTIVATION_ID);
        assertArrayEquals(SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8), privateKeysConverter.serialize(serverPrivateKeysActual));
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.ECDSA_P384).orElseThrow());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.MLDSA_65).orElseThrow());
    }

    @Test
    void testEncryptionAndDecryptionDifferentUserFail() throws Exception {
        final byte[] serverPrivateKeysBytes = SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeysRecord privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionAlgorithm.AEAD_KMAC, privateKeysEncrypted.encryptionAlgorithm());
        assertThrows(GenericServiceException.class, () ->
            privateKeysConverter.fromDBValue(privateKeysEncrypted, "test2", ACTIVATION_ID));
    }

    @Test
    void testEncryptionAndDecryptionDifferentActivationFailServerPrivateKeysConverter() throws Exception {
        final byte[] serverPrivateKeysBytes = SERVER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeysRecord privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, USER_ID, ACTIVATION_ID);

        assertEquals(EncryptionAlgorithm.AEAD_KMAC, privateKeysEncrypted.encryptionAlgorithm());

        assertThrows(GenericServiceException.class, () -> privateKeysConverter.fromDBValue(privateKeysEncrypted, USER_ID, "115286e0-e1c5-4ee1-8d1b-c6947cab0a56"));
    }

}
