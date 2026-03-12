/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.util.SdkConfigurationSerializer;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.function.ThrowingFunction;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AbstractApplicationServiceBehaviorTest {

    @Mock
    private PublicKeysConverter publicKeysConverter;

    @Mock
    private SdkConfigurationSerializer sdkConfigurationSerializer;

    @InjectMocks
    private ConcreteImpl tested;

    @BeforeAll
    static void setUpBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Minimal concrete subclass to make the abstract class instantiable. */
    static class ConcreteImpl extends AbstractApplicationServiceBehavior {}

    // -------------------------------------------------------------------------
    // getApplicationVersion
    // -------------------------------------------------------------------------

    @Test
    void getApplicationVersion_shouldMapAllEntityFieldsToApplicationVersion() {
        final ApplicationVersionEntity entity = new ApplicationVersionEntity();
        entity.setId("v1");
        entity.setApplicationKey("the-app-key");
        entity.setApplicationSecret("the-app-secret");
        entity.setSupported(true);

        final ApplicationVersion result = AbstractApplicationServiceBehavior.getApplicationVersion(entity, "sdk-config");

        assertEquals("v1", result.getApplicationVersionId());
        assertEquals("the-app-key", result.getApplicationKey());
        assertEquals("the-app-secret", result.getApplicationSecret());
        assertTrue(result.isSupported());
        assertEquals("sdk-config", result.getMobileSdkConfig());
    }

    @Test
    void getApplicationVersion_shouldSetSupportedFalse_whenEntityIsUnsupported() {
        final ApplicationVersionEntity entity = new ApplicationVersionEntity();
        entity.setId("v2");
        entity.setApplicationKey("key");
        entity.setApplicationSecret("secret");
        entity.setSupported(false);

        final ApplicationVersion result = AbstractApplicationServiceBehavior.getApplicationVersion(entity, "sdk");

        assertFalse(result.isSupported());
    }

    @Test
    void getApplicationVersion_shouldSetMobileSdkConfigToNull_whenNullIsPassed() {
        final ApplicationVersionEntity entity = new ApplicationVersionEntity();
        entity.setId("v3");
        entity.setApplicationKey("key");
        entity.setApplicationSecret("secret");
        entity.setSupported(true);

        final ApplicationVersion result = AbstractApplicationServiceBehavior.getApplicationVersion(entity, null);

        assertNull(result.getMobileSdkConfig());
    }

    // -------------------------------------------------------------------------
    // convertPublicKeyToBase64
    // -------------------------------------------------------------------------

    @Test
    void convertPublicKeyToBase64_shouldReturnBase64String_whenKeyExistsInRegistry() {
        final PublicKeyRegistry registry = new PublicKeyRegistry();
        registry.storePublicKey(KeyType.ECDSA_P384, mock(PublicKey.class));

        final byte[] keyBytes = {1, 2, 3, 4, 5};
        final ThrowingFunction<PublicKey, byte[]> converter = key -> keyBytes;

        final String result = tested.convertPublicKeyToBase64(registry, KeyType.ECDSA_P384, converter);

        assertEquals(Base64.getEncoder().encodeToString(keyBytes), result);
    }

    @Test
    void convertPublicKeyToBase64_shouldReturnNull_whenKeyIsAbsentFromRegistry() {
        final PublicKeyRegistry emptyRegistry = new PublicKeyRegistry();

        final String result = tested.convertPublicKeyToBase64(emptyRegistry, KeyType.ECDSA_P384, key -> new byte[0]);

        assertNull(result);
    }

    @Test
    void convertPublicKeyToBase64_shouldReturnNull_whenConverterThrowsException() {
        final PublicKeyRegistry registry = new PublicKeyRegistry();
        registry.storePublicKey(KeyType.ECDSA_P384, mock(PublicKey.class));

        final ThrowingFunction<PublicKey, byte[]> failingConverter = key -> {
            throw new RuntimeException("Conversion failed");
        };

        assertDoesNotThrow(() -> {
            final String result = tested.convertPublicKeyToBase64(registry, KeyType.ECDSA_P384, failingConverter);
            assertNull(result);
        });
    }

    @Test
    void convertPublicKeyToBase64_shouldPassActualKeyInstanceToConverter() {
        final PublicKeyRegistry registry = new PublicKeyRegistry();
        final PublicKey expectedKey = mock(PublicKey.class);
        registry.storePublicKey(KeyType.MLDSA_65, expectedKey);

        final PublicKey[] capturedKey = new PublicKey[1];
        final ThrowingFunction<PublicKey, byte[]> capturingConverter = key -> {
            capturedKey[0] = key;
            return new byte[]{42};
        };

        tested.convertPublicKeyToBase64(registry, KeyType.MLDSA_65, capturingConverter);

        assertSame(expectedKey, capturedKey[0]);
    }

    // -------------------------------------------------------------------------
    // getPublicKeys
    // -------------------------------------------------------------------------

    @Test
    void getPublicKeys_shouldReturnAllNullV4Keys_whenMasterPublicKeysIsNull() throws GenericServiceException {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        // masterPublicKeys is null (default)

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, "v3-public-key", List.of());

        assertNull(result.publicKeyP384());
        assertNull(result.publicKeyMlDsa65());
        assertNull(result.publicKeyMlDsa87());
    }

    @Test
    void getPublicKeys_shouldPreservePassedP256Key() throws GenericServiceException {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, "v3-p256-key", List.of());

        assertEquals("v3-p256-key", result.publicKeyP256());
    }

    @Test
    void getPublicKeys_shouldNotCallConverter_whenMasterPublicKeysIsNull() throws GenericServiceException {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();

        tested.getPublicKeys(keyPair, null, List.of(SharedSecretAlgorithm.EC_P384));

        verifyNoInteractions(publicKeysConverter);
    }

    @Test
    void getPublicKeys_shouldReturnP384Key_whenEc384AlgorithmIsSupported() throws Exception {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setMasterPublicKeys("public-keys-base64");

        final PublicKeyRegistry registry = new PublicKeyRegistry();
        registry.storePublicKey(KeyType.ECDSA_P384, generateEcP384KeyPair().getPublic());
        when(publicKeysConverter.fromDBValue("public-keys-base64")).thenReturn(registry);

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, null, List.of(SharedSecretAlgorithm.EC_P384));

        assertNotNull(result.publicKeyP384());
        assertNull(result.publicKeyMlDsa65());
        assertNull(result.publicKeyMlDsa87());
    }

    @Test
    void getPublicKeys_shouldReturnP384Key_whenEc384MlL3AlgorithmIsSupported() throws Exception {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setMasterPublicKeys("public-keys-base64");

        final PublicKeyRegistry registry = new PublicKeyRegistry();
        registry.storePublicKey(KeyType.ECDSA_P384, generateEcP384KeyPair().getPublic());
        registry.storePublicKey(KeyType.MLDSA_65, generateMlDsa65KeyPair().getPublic());
        when(publicKeysConverter.fromDBValue("public-keys-base64")).thenReturn(registry);

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, null, List.of(SharedSecretAlgorithm.EC_P384_ML_L3));

        assertNotNull(result.publicKeyP384());
        assertNotNull(result.publicKeyMlDsa65());
        assertNull(result.publicKeyMlDsa87());
    }

    @Test
    void getPublicKeys_shouldReturnP384AndMlDsa87Keys_whenEc384MlL5AlgorithmIsSupported() throws Exception {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setMasterPublicKeys("public-keys-base64");

        final PublicKeyRegistry registry = new PublicKeyRegistry();
        registry.storePublicKey(KeyType.ECDSA_P384, generateEcP384KeyPair().getPublic());
        registry.storePublicKey(KeyType.MLDSA_87, generateMlDsa87KeyPair().getPublic());
        when(publicKeysConverter.fromDBValue("public-keys-base64")).thenReturn(registry);

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, null, List.of(SharedSecretAlgorithm.EC_P384_ML_L5));

        assertNotNull(result.publicKeyP384());
        assertNull(result.publicKeyMlDsa65());
        assertNotNull(result.publicKeyMlDsa87());
    }

    @Test
    void getPublicKeys_shouldReturnNullP384_whenNoV4AlgorithmIsSupported() throws Exception {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setMasterPublicKeys("public-keys-base64");

        when(publicKeysConverter.fromDBValue("public-keys-base64")).thenReturn(new PublicKeyRegistry());

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, null, List.of(SharedSecretAlgorithm.EC_P256));

        assertNull(result.publicKeyP384());
        assertNull(result.publicKeyMlDsa65());
        assertNull(result.publicKeyMlDsa87());
    }

    @Test
    void getPublicKeys_shouldReturnNullP384_whenP384KeyIsMissingFromRegistry() throws Exception {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setMasterPublicKeys("public-keys-base64");

        when(publicKeysConverter.fromDBValue("public-keys-base64")).thenReturn(new PublicKeyRegistry());

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, null, List.of(SharedSecretAlgorithm.EC_P384));

        assertNull(result.publicKeyP384());
    }

    @Test
    void getPublicKeys_shouldReturnNullMlDsa65_whenMlDsa65KeyIsMissingFromRegistry() throws Exception {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setMasterPublicKeys("public-keys-base64");

        final PublicKeyRegistry registry = new PublicKeyRegistry();
        registry.storePublicKey(KeyType.ECDSA_P384, generateEcP384KeyPair().getPublic());
        // MLDSA_65 intentionally absent
        when(publicKeysConverter.fromDBValue("public-keys-base64")).thenReturn(registry);

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(keyPair, null, List.of(SharedSecretAlgorithm.EC_P384_ML_L3));

        assertNotNull(result.publicKeyP384());
        assertNull(result.publicKeyMlDsa65());
    }

    // -------------------------------------------------------------------------
    // getSdkConfigSerialized
    // -------------------------------------------------------------------------

    @Test
    void getSdkConfigSerialized_shouldCallSerializerWithAllFieldsFromEntityAndResult() throws Exception {
        final ApplicationVersionEntity version = new ApplicationVersionEntity();
        version.setApplicationKey("the-app-key");
        version.setApplicationSecret("the-app-secret");

        final AbstractApplicationServiceBehavior.Result result =
                new AbstractApplicationServiceBehavior.Result("p256-key", "p384-key", "mldsa65-key", "mldsa87-key");

        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized");

        tested.getSdkConfigSerialized(version, "p256-key", result);

        verify(sdkConfigurationSerializer).serialize(argThat(config ->
                "the-app-key".equals(config.appKey())
                && "the-app-secret".equals(config.appSecret())
                && "p256-key".equals(config.masterPublicKeyP256())
                && "p384-key".equals(config.masterPublicKeyP384())
                && "mldsa65-key".equals(config.masterPublicKeyMlDsa65())
                && "mldsa87-key".equals(config.masterPublicKeyMlDsa87())
        ));
    }

    @Test
    void getSdkConfigSerialized_shouldReturnSerializedStringFromSerializer() throws Exception {
        final ApplicationVersionEntity version = new ApplicationVersionEntity();
        version.setApplicationKey("app-key");
        version.setApplicationSecret("app-secret");

        final AbstractApplicationServiceBehavior.Result result =
                new AbstractApplicationServiceBehavior.Result(null, null, null, null);

        when(sdkConfigurationSerializer.serialize(any())).thenReturn("expected-serialized-config");

        final String serialized = tested.getSdkConfigSerialized(version, null, result);

        assertEquals("expected-serialized-config", serialized);
    }

    @Test
    void getSdkConfigSerialized_shouldPropagateExceptionFromSerializer() throws Exception {
        final ApplicationVersionEntity version = new ApplicationVersionEntity();
        version.setApplicationKey("app-key");
        version.setApplicationSecret("app-secret");

        final AbstractApplicationServiceBehavior.Result result =
                new AbstractApplicationServiceBehavior.Result(null, null, null, null);

        final GenericServiceException expected = new GenericServiceException("ERR", "serialization failed");
        when(sdkConfigurationSerializer.serialize(any())).thenThrow(expected);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.getSdkConfigSerialized(version, null, result)
        );
        assertSame(expected, thrown);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static KeyPair generateEcP384KeyPair() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        return generator.generateKeyPair();
    }

    private static KeyPair generateMlDsa65KeyPair() throws Exception {
        final com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation serverActivation =
                new com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation();
        return serverActivation.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L3);
    }

    private static KeyPair generateMlDsa87KeyPair() throws Exception {
        final com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation serverActivation =
                new com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation();
        return serverActivation.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L5);
    }

}
