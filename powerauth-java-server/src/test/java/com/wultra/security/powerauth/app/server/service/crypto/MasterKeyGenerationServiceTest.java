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
 */
package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.converter.MasterPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeysRecord;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MasterKeyGenerationServiceTest {

    @Mock
    private MasterKeyPairRepository masterKeyPairRepository;

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private MasterPrivateKeysConverter masterPrivateKeysConverter;

    @Mock
    private PublicKeysConverter publicKeysConverter;

    @Mock
    private AlgorithmQueryService algorithmQueryService;

    @InjectMocks
    private MasterKeyGenerationService tested;

    @BeforeAll
    static void setUpBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void generateMasterKeyPairs_shouldCreateNewEntityAndGenerateV3AndV4KeysForSupportedAlgorithms() throws Exception {
        final String applicationId = "app-new";
        final ApplicationEntity application = application(applicationId);

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256, SharedSecretAlgorithm.EC_P384));
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "private-registry-base64"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("public-registry-base64");

        final MasterKeyPairEntity result = tested.generateMasterKeyPairs(application);

        assertNotNull(result);
        assertSame(application, result.getApplication());
        assertEquals(applicationId + " Default Keypair", result.getName());
        assertNotNull(result.getTimestampCreated());
        assertNotNull(result.getMasterKeyPrivateBase64());
        assertNotNull(result.getMasterKeyPublicBase64());
        assertEquals("private-registry-base64", result.getMasterPrivateKeys());
        assertEquals(EncryptionAlgorithm.AEAD_KMAC, result.getMasterPrivateKeysEncryption());
        assertEquals("public-registry-base64", result.getMasterPublicKeys());

        final ArgumentCaptor<PrivateKeyRegistry> privateRegistryCaptor = ArgumentCaptor.forClass(PrivateKeyRegistry.class);
        final ArgumentCaptor<PublicKeyRegistry> publicRegistryCaptor = ArgumentCaptor.forClass(PublicKeyRegistry.class);
        verify(masterPrivateKeysConverter).toDBValue(privateRegistryCaptor.capture(), eq(applicationId));
        verify(publicKeysConverter).toDBValue(publicRegistryCaptor.capture());

        assertTrue(privateRegistryCaptor.getValue().getPrivateKey(KeyType.ECDSA_P384).isPresent());
        assertTrue(publicRegistryCaptor.getValue().getPublicKey(KeyType.ECDSA_P384).isPresent());
    }

    @Test
    void generateMasterKeyPairs_shouldReuseExistingRegistriesAndKeepExistingV3Keys() throws Exception {
        final String applicationId = "app-existing";
        final ApplicationEntity application = application(applicationId);

        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        existing.setApplication(application);
        existing.setMasterKeyPrivateBase64("existing-v3-private");
        existing.setMasterKeyPublicBase64("existing-v3-public");
        existing.setMasterPrivateKeys("existing-private-registry");
        existing.setMasterPrivateKeysEncryption(EncryptionAlgorithm.AEAD_KMAC);
        existing.setMasterPublicKeys("existing-public-registry");

        final PrivateKeyRegistry privateRegistry = new PrivateKeyRegistry();
        final PublicKeyRegistry publicRegistry = new PublicKeyRegistry();
        final KeyPair ecKeyPair = generateEcP384KeyPair();
        privateRegistry.storePrivateKey(KeyType.ECDSA_P384, ecKeyPair.getPrivate());
        publicRegistry.storePublicKey(KeyType.ECDSA_P384, ecKeyPair.getPublic());

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(existing);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256, SharedSecretAlgorithm.EC_P384));
        when(masterPrivateKeysConverter.fromDBValue(any(PrivateKeysRecord.class), eq(applicationId))).thenReturn(privateRegistry);
        when(publicKeysConverter.fromDBValue("existing-public-registry")).thenReturn(publicRegistry);
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "updated-private-registry"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("updated-public-registry");

        final MasterKeyPairEntity result = tested.generateMasterKeyPairs(application);

        assertSame(existing, result);
        assertEquals("existing-v3-private", result.getMasterKeyPrivateBase64());
        assertEquals("existing-v3-public", result.getMasterKeyPublicBase64());
        assertEquals("updated-private-registry", result.getMasterPrivateKeys());
        assertEquals("updated-public-registry", result.getMasterPublicKeys());

        verify(masterPrivateKeysConverter).fromDBValue(
                argThat(record -> record.encryptionAlgorithm() == EncryptionAlgorithm.AEAD_KMAC
                        && "existing-private-registry".equals(record.privateKeysBase64())),
                eq(applicationId)
        );
    }

    @Test
    void generateMasterKeyPairs_shouldGenerateMissingMlDsa87KeyWhenMlL5AlgorithmIsSupported() throws Exception {
        final String applicationId = "app-pqc";
        final ApplicationEntity application = application(applicationId);

        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        existing.setApplication(application);
        existing.setMasterPrivateKeys("existing-private-registry");
        existing.setMasterPrivateKeysEncryption(EncryptionAlgorithm.AEAD_KMAC);
        existing.setMasterPublicKeys("existing-public-registry");

        final PrivateKeyRegistry privateRegistry = new PrivateKeyRegistry();
        final PublicKeyRegistry publicRegistry = new PublicKeyRegistry();
        final KeyPair ecKeyPair = generateEcP384KeyPair();
        privateRegistry.storePrivateKey(KeyType.ECDSA_P384, ecKeyPair.getPrivate());
        publicRegistry.storePublicKey(KeyType.ECDSA_P384, ecKeyPair.getPublic());

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(existing);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P384_ML_L5));
        when(masterPrivateKeysConverter.fromDBValue(any(PrivateKeysRecord.class), eq(applicationId))).thenReturn(privateRegistry);
        when(publicKeysConverter.fromDBValue("existing-public-registry")).thenReturn(publicRegistry);
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "updated-private-registry"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("updated-public-registry");

        tested.generateMasterKeyPairs(application);

        final ArgumentCaptor<PrivateKeyRegistry> privateRegistryCaptor = ArgumentCaptor.forClass(PrivateKeyRegistry.class);
        final ArgumentCaptor<PublicKeyRegistry> publicRegistryCaptor = ArgumentCaptor.forClass(PublicKeyRegistry.class);
        verify(masterPrivateKeysConverter).toDBValue(privateRegistryCaptor.capture(), eq(applicationId));
        verify(publicKeysConverter).toDBValue(publicRegistryCaptor.capture());

        assertTrue(privateRegistryCaptor.getValue().getPrivateKey(KeyType.ECDSA_P384).isPresent());
        assertTrue(publicRegistryCaptor.getValue().getPublicKey(KeyType.ECDSA_P384).isPresent());
        assertTrue(privateRegistryCaptor.getValue().getPrivateKey(KeyType.MLDSA_87).isPresent());
        assertTrue(publicRegistryCaptor.getValue().getPublicKey(KeyType.MLDSA_87).isPresent());
    }

    @Test
    void generateMasterKeyPairs_shouldKeepV3KeysEmptyWhenNoAlgorithmsAreSupported() throws Exception {
        final String applicationId = "app-no-algorithms";
        final ApplicationEntity application = application(applicationId);

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "private-registry-base64"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("public-registry-base64");

        final MasterKeyPairEntity result = tested.generateMasterKeyPairs(application);

        assertNull(result.getMasterKeyPrivateBase64());
        assertNull(result.getMasterKeyPublicBase64());

        final ArgumentCaptor<PrivateKeyRegistry> privateRegistryCaptor = ArgumentCaptor.forClass(PrivateKeyRegistry.class);
        final ArgumentCaptor<PublicKeyRegistry> publicRegistryCaptor = ArgumentCaptor.forClass(PublicKeyRegistry.class);
        verify(masterPrivateKeysConverter).toDBValue(privateRegistryCaptor.capture(), eq(applicationId));
        verify(publicKeysConverter).toDBValue(publicRegistryCaptor.capture());

        assertTrue(privateRegistryCaptor.getValue().getPrivateKeys().isEmpty());
        assertTrue(publicRegistryCaptor.getValue().getPublicKeys().isEmpty());
    }

    @Test
    void generateMasterKeyPairs_shouldPropagateGenericServiceExceptionWhenPrivateRegistryCannotBeLoaded() throws Exception {
        final String applicationId = "app-failure";
        final ApplicationEntity application = application(applicationId);

        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        existing.setApplication(application);
        existing.setMasterPrivateKeys("existing-private-registry");
        existing.setMasterPrivateKeysEncryption(EncryptionAlgorithm.AEAD_KMAC);
        existing.setMasterPublicKeys("existing-public-registry");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(existing);
        when(masterPrivateKeysConverter.fromDBValue(any(PrivateKeysRecord.class), eq(applicationId)))
                .thenThrow(new GenericServiceException("ERR", "failed"));

        assertThrows(GenericServiceException.class, () -> tested.generateMasterKeyPairs(application));
    }

    @Test
    void saveMasterKeyPairs_shouldPersistGeneratedEntity() throws Exception {
        final String applicationId = "app-save";
        final ApplicationEntity application = application(applicationId);

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "private-registry-base64"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("public-registry-base64");

        tested.saveMasterKeyPairs(application);

        verify(masterKeyPairRepository).save(any(MasterKeyPairEntity.class));
    }

    @Test
    void saveMasterKeyPairs_shouldSaveEntityWithCorrectApplicationAssociation() throws Exception {
        final String applicationId = "app-save-assoc";
        final ApplicationEntity application = application(applicationId);

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "private-registry-base64"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("public-registry-base64");

        tested.saveMasterKeyPairs(application);

        final ArgumentCaptor<MasterKeyPairEntity> entityCaptor = ArgumentCaptor.forClass(MasterKeyPairEntity.class);
        verify(masterKeyPairRepository).save(entityCaptor.capture());
        assertSame(application, entityCaptor.getValue().getApplication());
        assertEquals(applicationId + " Default Keypair", entityCaptor.getValue().getName());
        assertNotNull(entityCaptor.getValue().getTimestampCreated());
    }

    @Test
    void saveMasterKeyPairs_shouldSaveEntityWithV3Keys_whenEcP256AlgorithmIsSupported() throws Exception {
        final String applicationId = "app-save-v3";
        final ApplicationEntity application = application(applicationId);

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "private-registry-base64"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("public-registry-base64");

        tested.saveMasterKeyPairs(application);

        final ArgumentCaptor<MasterKeyPairEntity> entityCaptor = ArgumentCaptor.forClass(MasterKeyPairEntity.class);
        verify(masterKeyPairRepository).save(entityCaptor.capture());
        assertNotNull(entityCaptor.getValue().getMasterKeyPrivateBase64());
        assertNotNull(entityCaptor.getValue().getMasterKeyPublicBase64());
    }

    @Test
    void saveMasterKeyPairs_shouldNotCallSave_whenGenerationThrowsException() throws Exception {
        final String applicationId = "app-save-fail";
        final ApplicationEntity application = application(applicationId);

        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        existing.setApplication(application);
        existing.setMasterPrivateKeys("existing-private-registry");
        existing.setMasterPrivateKeysEncryption(EncryptionAlgorithm.AEAD_KMAC);
        existing.setMasterPublicKeys("existing-public-registry");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(existing);
        when(masterPrivateKeysConverter.fromDBValue(any(PrivateKeysRecord.class), eq(applicationId)))
                .thenThrow(new GenericServiceException("ERR", "failed"));

        assertThrows(GenericServiceException.class, () -> tested.saveMasterKeyPairs(application));
        verify(masterKeyPairRepository, never()).save(any());
    }

    @Test
    void saveMasterKeyPairs_shouldSaveUpdatedExistingEntity_whenKeyPairAlreadyExists() throws Exception {
        final String applicationId = "app-save-existing";
        final ApplicationEntity application = application(applicationId);

        final MasterKeyPairEntity existing = new MasterKeyPairEntity();
        existing.setApplication(application);
        existing.setMasterKeyPrivateBase64("existing-v3-private");
        existing.setMasterKeyPublicBase64("existing-v3-public");
        existing.setMasterPrivateKeys("existing-private-registry");
        existing.setMasterPrivateKeysEncryption(EncryptionAlgorithm.AEAD_KMAC);
        existing.setMasterPublicKeys("existing-public-registry");

        final PrivateKeyRegistry privateRegistry = new PrivateKeyRegistry();
        final PublicKeyRegistry publicRegistry = new PublicKeyRegistry();
        final KeyPair ecKeyPair = generateEcP384KeyPair();
        privateRegistry.storePrivateKey(KeyType.ECDSA_P384, ecKeyPair.getPrivate());
        publicRegistry.storePublicKey(KeyType.ECDSA_P384, ecKeyPair.getPublic());

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(existing);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256, SharedSecretAlgorithm.EC_P384));
        when(masterPrivateKeysConverter.fromDBValue(any(PrivateKeysRecord.class), eq(applicationId))).thenReturn(privateRegistry);
        when(publicKeysConverter.fromDBValue("existing-public-registry")).thenReturn(publicRegistry);
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "updated-private-registry"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("updated-public-registry");

        tested.saveMasterKeyPairs(application);

        final ArgumentCaptor<MasterKeyPairEntity> entityCaptor = ArgumentCaptor.forClass(MasterKeyPairEntity.class);
        verify(masterKeyPairRepository).save(entityCaptor.capture());
        assertSame(existing, entityCaptor.getValue());
        assertEquals("updated-private-registry", entityCaptor.getValue().getMasterPrivateKeys());
        assertEquals("updated-public-registry", entityCaptor.getValue().getMasterPublicKeys());
    }

    @Test
    void generateAndSaveMasterKeyPairs_shouldReturnAndPersistGeneratedEntity() throws Exception {
        final String applicationId = "app-generate-save";
        final ApplicationEntity application = application(applicationId);

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId)).thenReturn(null);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());
        when(masterPrivateKeysConverter.toDBValue(any(PrivateKeyRegistry.class), eq(applicationId)))
                .thenReturn(new PrivateKeysRecord(EncryptionAlgorithm.AEAD_KMAC, "private-registry-base64"));
        when(publicKeysConverter.toDBValue(any(PublicKeyRegistry.class))).thenReturn("public-registry-base64");
        when(masterKeyPairRepository.save(any(MasterKeyPairEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        final MasterKeyPairEntity result = tested.generateAndSaveMasterKeyPairs(application);

        assertNotNull(result);
        verify(masterKeyPairRepository).save(same(result));
    }

    private ApplicationEntity application(String applicationId) {
        final ApplicationEntity application = new ApplicationEntity();
        application.setId(applicationId);
        return application;
    }

    private KeyPair generateEcP384KeyPair() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        return generator.generateKeyPair();
    }
}

