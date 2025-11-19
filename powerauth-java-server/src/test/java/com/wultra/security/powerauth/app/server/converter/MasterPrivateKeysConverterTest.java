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

import static com.wultra.security.powerauth.app.server.util.AssertionUtils.assertThrowsOrNotEqual;
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

    private static final String MASTER_PRIVATE_KEYS_JSON = "{\"privateKeys\":{\"ECDSA_P384\":\"" + ECDSA_PRIVATE_KEY + "\",\"MLDSA_65\":\"" + MLDSA_PRIVATE_KEY + "\"}}";
    private static final String MASTER_PRIVATE_KEYS_AES_HMAC_ENCRYPTED = "FS5fGCes4T7aiT2yCMVU49VNPuZk5uYrCKHrV/rcn6rsQCJN0e5IGvUzEiREEZ8I0LWppa5T/pqAD2KTbbc3wylUgQ30WPA6smBjecpoxq0RynVtZKnCVIGqSTQiUPt2KPcIs+QNOXJfAPUCF2pQBjeLBEPK5/vFaBqagnc3qO04BND1VKWYgdBsYAtQtbaAGWgGApJE/fE37ahykenGqT20plPvGu+OX3mqkdnrq0Sa28ZNeQeK8eVSVmPOgQ0zafMmMXFzN+1uxbPHxdwJ4w==";
    private static final String MASTER_PRIVATE_KEYS_AEAD_KMAC_ENCRYPTED = "ng5xKplr3Nv+zzvoqxJJI1j1swUcs55/duLXpVkyCqwSvh7A1oGT2mWZqEQ0Vn0pA4JGZrQI/w4RbUIWDFzwhli09EzVTsS7EW82ep7JSmlkifp7hWdKqQqwAlvA05iHKw16PdxZ51KXZKwhG0uSpJKjRCg3U+wC6itBVs3fcAniQrBEs9NNu9/n6E0MOyJpy0pFttW8YVakkqYlupfVBw7Uo0REXCgyZ8+iw/N9lug4JwK17xrf6gNDcK1utzzXx3s4XBEGDtjS0xmhTea4hUN9n2mp0IO9JpH453FhLyTkyTij9wMv";

    private static final String APPLICATION_ID = "test";

    @Autowired
    private MasterPrivateKeysConverter privateKeysConverter;

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
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, APPLICATION_ID);
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
        final byte[] serverPrivateKeysBytes = MASTER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeysRecord privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, APPLICATION_ID);
        assertEquals(EncryptionAlgorithm.AEAD_KMAC, privateKeysEncrypted.encryptionAlgorithm());
        assertNotEquals(MASTER_PRIVATE_KEYS_JSON, privateKeysEncrypted.privateKeysBase64());
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, APPLICATION_ID);
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.ECDSA_P384).get());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.MLDSA_65).get());
    }

    @Test
    void testFromDbValueEncryptionAesHmac() throws Exception {
        final PrivateKeysRecord privateKeysEncrypted = new PrivateKeysRecord(EncryptionAlgorithm.AES_HMAC, MASTER_PRIVATE_KEYS_AES_HMAC_ENCRYPTED);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, APPLICATION_ID);
        assertArrayEquals(MASTER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8), privateKeysConverter.serialize(serverPrivateKeysActual));
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.ECDSA_P384).get());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.MLDSA_65).get());
    }

    @Test
    void testFromDbValueEncryptionAeadKmac() throws Exception {
        final PrivateKeysRecord privateKeysEncrypted = new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, MASTER_PRIVATE_KEYS_AEAD_KMAC_ENCRYPTED);
        final PrivateKeyRegistry serverPrivateKeysActual = privateKeysConverter.fromDBValue(privateKeysEncrypted, APPLICATION_ID);
        assertArrayEquals(MASTER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8), privateKeysConverter.serialize(serverPrivateKeysActual));
        final PrivateKey privateKeyEcExpected = KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, Base64.getDecoder().decode(ECDSA_PRIVATE_KEY));
        assertEquals(privateKeyEcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.ECDSA_P384).get());
        final PrivateKey privateKeyPqcExpected = KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(Base64.getDecoder().decode(MLDSA_PRIVATE_KEY));
        assertEquals(privateKeyPqcExpected, serverPrivateKeysActual.getPrivateKey(KeyType.MLDSA_65).get());
    }

    @Test
    void testEncryptionAndDecryptionDifferentApplicationIdFail() throws Exception {
        final byte[] serverPrivateKeysBytes = MASTER_PRIVATE_KEYS_JSON.getBytes(StandardCharsets.UTF_8);
        final PrivateKeysRecord privateKeysEncrypted = privateKeysConverter.toDBValue(serverPrivateKeysBytes, APPLICATION_ID);

        assertEquals(EncryptionAlgorithm.AEAD_KMAC, privateKeysEncrypted.encryptionAlgorithm());
        assertThrowsOrNotEqual(GenericServiceException.class,
                () -> privateKeysConverter.fromDBValue(privateKeysEncrypted, "test2"),
                serverPrivateKeysBytes);
    }

}
