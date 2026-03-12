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
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmQueryService;
import com.wultra.security.powerauth.app.server.service.crypto.MasterKeyGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.util.SdkConfigurationSerializer;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApplicationServiceBehaviorTest {

    @Mock
    private MasterKeyGenerationService masterKeyGenerationService;
    @Mock
    private LocalizationProvider localizationProvider;
    @Mock
    private ApplicationRepository applicationRepository;
    @Mock
    private ApplicationVersionRepository applicationVersionRepository;
    @Mock
    private AlgorithmQueryService algorithmQueryService;
    @Mock
    private PublicKeysConverter publicKeysConverter;
    @Mock
    private SdkConfigurationSerializer sdkConfigurationSerializer;

    @InjectMocks
    private ApplicationServiceBehavior tested;

    @BeforeAll
    static void setUpBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void createApplication_shouldReturnApplicationIdInResponse() throws Exception {
        final String applicationId = "app-create";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = keyPairWithV3Key("v3-public");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        final CreateApplicationResponse response = tested.createApplication(createRequest(applicationId));

        assertEquals(applicationId, response.getApplicationId());
    }

    @Test
    void createApplication_shouldIncludeSupportedAlgorithmsInResponse() throws Exception {
        final String applicationId = "app-algos";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = keyPairWithV3Key("v3-public");
        final List<SharedSecretAlgorithm> algorithms = List.of(SharedSecretAlgorithm.EC_P256, SharedSecretAlgorithm.EC_P384);

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(algorithms);
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        final CreateApplicationResponse response = tested.createApplication(createRequest(applicationId));

        assertEquals(
                List.of(SharedSecretAlgorithm.EC_P256.name(), SharedSecretAlgorithm.EC_P384.name()),
                response.getSupportedAlgorithms()
        );
    }

    @Test
    void createApplication_shouldIncludeDefaultVersionInResponse() throws Exception {
        final String applicationId = "app-version";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = keyPairWithV3Key("v3-public");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        final CreateApplicationResponse response = tested.createApplication(createRequest(applicationId));

        assertFalse(response.getVersions().isEmpty());
        assertEquals("default", response.getVersions().get(0).getApplicationVersionId());
        assertTrue(response.getVersions().get(0).isSupported());
        assertEquals("serialized-sdk", response.getVersions().get(0).getMobileSdkConfig());
    }

    @Test
    void createApplication_shouldSaveDefaultVersionEntityWithCorrectFields() throws Exception {
        final String applicationId = "app-save-version";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = keyPairWithV3Key("v3-public");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        tested.createApplication(createRequest(applicationId));

        final ArgumentCaptor<ApplicationVersionEntity> versionCaptor = ArgumentCaptor.forClass(ApplicationVersionEntity.class);
        verify(applicationVersionRepository).save(versionCaptor.capture());
        final ApplicationVersionEntity saved = versionCaptor.getValue();
        assertSame(savedApp, saved.getApplication());
        assertEquals("default", saved.getId());
        assertTrue(saved.getSupported());
        assertNotNull(saved.getApplicationKey());
        assertNotNull(saved.getApplicationSecret());
    }

    @Test
    void createApplication_shouldGenerateDifferentAppKeyAndSecret() throws Exception {
        final String applicationId = "app-keys";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = keyPairWithV3Key("v3-public");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(List.of());
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        tested.createApplication(createRequest(applicationId));

        final ArgumentCaptor<ApplicationVersionEntity> versionCaptor = ArgumentCaptor.forClass(ApplicationVersionEntity.class);
        verify(applicationVersionRepository).save(versionCaptor.capture());
        final ApplicationVersionEntity saved = versionCaptor.getValue();
        assertNotEquals(saved.getApplicationKey(), saved.getApplicationSecret());
    }

    @Test
    void createApplication_shouldPassNullPublicKeyToSdkConfig_whenEc256IsNotSupported() throws Exception {
        final String applicationId = "app-no-p256";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = keyPairWithV3Key("v3-public");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(List.of());
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        tested.createApplication(createRequest(applicationId));

        verify(sdkConfigurationSerializer).serialize(argThat(config -> config.masterPublicKeyP256() == null));
    }

    @Test
    void createApplication_shouldPassV3PublicKeyToSdkConfig_whenEc256IsSupported() throws Exception {
        final String applicationId = "app-with-p256";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = keyPairWithV3Key("v3-public-key-base64");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        tested.createApplication(createRequest(applicationId));

        verify(sdkConfigurationSerializer).serialize(argThat(config -> "v3-public-key-base64".equals(config.masterPublicKeyP256())));
    }

    @Test
    void createApplication_shouldIncludeP384PublicKeyInSdkConfig_whenEc384IsSupported() throws Exception {
        final String applicationId = "app-p384";
        final ApplicationEntity savedApp = applicationEntity(applicationId);

        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setApplication(savedApp);
        keyPair.setMasterPublicKeys("public-keys-registry-base64");

        final KeyPair ecP384KeyPair = generateEcP384KeyPair();
        final PublicKeyRegistry registry = new PublicKeyRegistry();
        registry.storePublicKey(KeyType.ECDSA_P384, ecP384KeyPair.getPublic());

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(savedApp)).thenReturn(List.of(SharedSecretAlgorithm.EC_P384));
        when(publicKeysConverter.fromDBValue("public-keys-registry-base64")).thenReturn(registry);
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk");

        tested.createApplication(createRequest(applicationId));

        verify(sdkConfigurationSerializer).serialize(argThat(config -> config.masterPublicKeyP384() != null));
    }

    @Test
    void createApplication_shouldThrowDuplicateException_whenApplicationAlreadyExists() throws Exception {
        final String applicationId = "app-duplicate";
        final GenericServiceException expected = new GenericServiceException(ServiceError.DUPLICATE_APPLICATION, "Duplicate");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.of(applicationEntity(applicationId)));
        when(localizationProvider.buildExceptionForCode(ServiceError.DUPLICATE_APPLICATION)).thenReturn(expected);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.createApplication(createRequest(applicationId))
        );
        assertSame(expected, thrown);
    }

    @Test
    void createApplication_shouldNotSaveApplication_whenDuplicateDetected() throws Exception {
        final String applicationId = "app-duplicate-no-save";
        final GenericServiceException duplicateException = new GenericServiceException(ServiceError.DUPLICATE_APPLICATION, "Duplicate");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.of(applicationEntity(applicationId)));
        when(localizationProvider.buildExceptionForCode(ServiceError.DUPLICATE_APPLICATION)).thenReturn(duplicateException);

        assertThrows(GenericServiceException.class, () -> tested.createApplication(createRequest(applicationId)));

        verify(applicationRepository, never()).save(any());
        verifyNoInteractions(masterKeyGenerationService);
        verifyNoInteractions(applicationVersionRepository);
    }

    @Test
    void createApplication_shouldPropagateGenericServiceException_whenKeyGenerationFails() throws Exception {
        final String applicationId = "app-keygen-fail";
        final ApplicationEntity savedApp = applicationEntity(applicationId);
        final GenericServiceException expected = new GenericServiceException(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR, "Crypto failed");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenReturn(savedApp);
        when(masterKeyGenerationService.generateAndSaveMasterKeyPairs(savedApp)).thenThrow(expected);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.createApplication(createRequest(applicationId))
        );
        assertSame(expected, thrown);
    }

    @Test
    void createApplication_shouldRethrowRuntimeException() throws Exception {
        final String applicationId = "app-runtime-fail";
        final RuntimeException expected = new RuntimeException("DB failure");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(applicationRepository.save(any())).thenThrow(expected);

        final RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> tested.createApplication(createRequest(applicationId))
        );
        assertSame(expected, thrown);
    }

    private static CreateApplicationRequest createRequest(String applicationId) {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId(applicationId);
        return request;
    }

    private static ApplicationEntity applicationEntity(String applicationId) {
        final ApplicationEntity entity = new ApplicationEntity();
        entity.setId(applicationId);
        return entity;
    }

    private static MasterKeyPairEntity keyPairWithV3Key(String publicKeyBase64) {
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setMasterKeyPrivateBase64("v3-private");
        keyPair.setMasterKeyPublicBase64(publicKeyBase64);
        return keyPair;
    }

    private static KeyPair generateEcP384KeyPair() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        return generator.generateKeyPair();
    }

}
