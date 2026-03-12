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
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmQueryService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
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

import java.security.Security;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AbstractApplicationDetailServiceBehaviorTest {

    @Mock
    private LocalizationProvider localizationProvider;
    @Mock
    private ApplicationRepository applicationRepository;
    @Mock
    private MasterKeyPairRepository masterKeyPairRepository;
    @Mock
    private ApplicationVersionRepository applicationVersionRepository;
    @Mock
    private AlgorithmQueryService algorithmQueryService;
    @Mock
    private SdkConfigurationSerializer sdkConfigurationSerializer;
    @Mock
    private PublicKeysConverter publicKeysConverter;

    @InjectMocks
    private ConcreteImpl tested;

    @BeforeAll
    static void setUpBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Minimal concrete subclass to make the abstract class instantiable. */
    static class ConcreteImpl extends AbstractApplicationDetailServiceBehavior {}

    // -------------------------------------------------------------------------
    // findApplicationById
    // -------------------------------------------------------------------------

    @Test
    void findApplicationById_shouldReturnEntity_whenApplicationExists() throws GenericServiceException {
        final String applicationId = "app-exists";
        final ApplicationEntity entity = applicationEntity(applicationId);
        when(applicationRepository.findById(applicationId)).thenReturn(Optional.of(entity));

        final ApplicationEntity result = tested.findApplicationById(applicationId);

        assertSame(entity, result);
    }

    @Test
    void findApplicationById_shouldThrowGenericServiceException_whenApplicationDoesNotExist() throws GenericServiceException {
        final String applicationId = "app-missing";
        final GenericServiceException expected =
                new GenericServiceException(ServiceError.INVALID_APPLICATION, "Not found");

        when(applicationRepository.findById(applicationId)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION)).thenReturn(expected);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.findApplicationById(applicationId)
        );
        assertSame(expected, thrown);
    }

    @Test
    void findApplicationById_shouldQueryRepositoryWithExactId() throws GenericServiceException {
        final String applicationId = "exact-app-id";
        final ApplicationEntity entity = applicationEntity(applicationId);
        when(applicationRepository.findById(applicationId)).thenReturn(Optional.of(entity));

        tested.findApplicationById(applicationId);

        verify(applicationRepository).findById(applicationId);
        verifyNoMoreInteractions(applicationRepository);
    }

    // -------------------------------------------------------------------------
    // supportedAlgorithms
    // -------------------------------------------------------------------------

    @Test
    void supportedAlgorithms_shouldDelegateToAlgorithmQueryService() {
        final ApplicationEntity application = applicationEntity("app");
        final List<SharedSecretAlgorithm> expected = List.of(SharedSecretAlgorithm.EC_P256, SharedSecretAlgorithm.EC_P384);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(expected);

        final List<SharedSecretAlgorithm> result = tested.supportedAlgorithms(application);

        assertSame(expected, result);
        verify(algorithmQueryService).getSupportedAlgorithms(application);
    }

    @Test
    void supportedAlgorithms_shouldReturnEmptyList_whenNoneSupported() {
        final ApplicationEntity application = applicationEntity("app-no-algos");
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());

        final List<SharedSecretAlgorithm> result = tested.supportedAlgorithms(application);

        assertTrue(result.isEmpty());
    }

    // -------------------------------------------------------------------------
    // getPublicKeys(String, List)
    // -------------------------------------------------------------------------

    @Test
    void getPublicKeys_shouldThrowGenericServiceException_whenNoKeyPairFound() throws GenericServiceException {
        final String applicationId = "app-no-keys";
        final GenericServiceException expected =
                new GenericServiceException(ServiceError.NO_MASTER_SERVER_KEYPAIR, "No key pair");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(null);
        when(localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR)).thenReturn(expected);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.getPublicKeys(applicationId, List.of(SharedSecretAlgorithm.EC_P256))
        );
        assertSame(expected, thrown);
    }

    @Test
    void getPublicKeys_shouldReturnP256Key_whenEc256AlgorithmIsSupported() throws GenericServiceException {
        final String applicationId = "app-p256";
        final MasterKeyPairEntity keyPair = keyPairWithV3Key(applicationId, "v3-pub-key");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPair);

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(applicationId, List.of(SharedSecretAlgorithm.EC_P256));

        assertEquals("v3-pub-key", result.publicKeyP256());
    }

    @Test
    void getPublicKeys_shouldReturnNullP256_whenEc256IsNotInSupportedAlgorithms() throws GenericServiceException {
        final String applicationId = "app-no-p256";
        final MasterKeyPairEntity keyPair = keyPairWithV3Key(applicationId, "v3-pub-key");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPair);

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(applicationId, List.of(SharedSecretAlgorithm.EC_P384));

        assertNull(result.publicKeyP256());
    }

    @Test
    void getPublicKeys_shouldReturnNullForAllKeys_whenNoAlgorithmsSupported() throws GenericServiceException {
        final String applicationId = "app-empty-algos";
        final MasterKeyPairEntity keyPair = keyPairWithV3Key(applicationId, "v3-pub-key");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPair);

        final AbstractApplicationServiceBehavior.Result result =
                tested.getPublicKeys(applicationId, List.of());

        assertNull(result.publicKeyP256());
        assertNull(result.publicKeyP384());
        assertNull(result.publicKeyMlDsa65());
        assertNull(result.publicKeyMlDsa87());
    }

    @Test
    void getPublicKeys_shouldQueryRepositoryWithExactApplicationId() throws GenericServiceException {
        final String applicationId = "exact-app-for-keys";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-key"));

        tested.getPublicKeys(applicationId, List.of());

        verify(masterKeyPairRepository).findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
    }

    // -------------------------------------------------------------------------
    // versions
    // -------------------------------------------------------------------------

    @Test
    void versions_shouldReturnEmptyList_whenNoVersionsExist() throws GenericServiceException {
        final String applicationId = "app-no-versions";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-key"));
        when(applicationVersionRepository.findByApplicationId(applicationId)).thenReturn(List.of());

        final List<ApplicationVersion> result = tested.versions(applicationId, List.of());

        assertTrue(result.isEmpty());
    }

    @Test
    void versions_shouldReturnMappedApplicationVersion_forEachVersionEntity() throws GenericServiceException {
        final String applicationId = "app-with-versions";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-key"));

        final ApplicationVersionEntity v1 = versionEntity("v1", "key-1", "secret-1", true);
        final ApplicationVersionEntity v2 = versionEntity("v2", "key-2", "secret-2", false);
        when(applicationVersionRepository.findByApplicationId(applicationId)).thenReturn(List.of(v1, v2));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("sdk-config");

        final List<ApplicationVersion> result = tested.versions(applicationId, List.of());

        assertEquals(2, result.size());
    }

    @Test
    void versions_shouldMapVersionEntityFieldsCorrectly() throws GenericServiceException {
        final String applicationId = "app-version-fields";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-key"));

        final ApplicationVersionEntity entity = versionEntity("default", "the-app-key", "the-app-secret", true);
        when(applicationVersionRepository.findByApplicationId(applicationId)).thenReturn(List.of(entity));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("serialized-sdk-config");

        final List<ApplicationVersion> result = tested.versions(applicationId, List.of());

        final ApplicationVersion version = result.get(0);
        assertEquals("default", version.getApplicationVersionId());
        assertEquals("the-app-key", version.getApplicationKey());
        assertEquals("the-app-secret", version.getApplicationSecret());
        assertTrue(version.isSupported());
        assertEquals("serialized-sdk-config", version.getMobileSdkConfig());
    }

    @Test
    void versions_shouldPassVersionAppKeyAndSecretToSdkConfigSerializer() throws GenericServiceException {
        final String applicationId = "app-sdk-config";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-key"));

        final ApplicationVersionEntity entity = versionEntity("v1", "specific-app-key", "specific-app-secret", true);
        when(applicationVersionRepository.findByApplicationId(applicationId)).thenReturn(List.of(entity));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("sdk");

        tested.versions(applicationId, List.of());

        verify(sdkConfigurationSerializer).serialize(argThat(config ->
                "specific-app-key".equals(config.appKey())
                && "specific-app-secret".equals(config.appSecret())
        ));
    }

    @Test
    void versions_shouldIncludeP256KeyInSdkConfig_whenEc256IsSupported() throws GenericServiceException {
        final String applicationId = "app-p256-sdk";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-p256-key"));

        when(applicationVersionRepository.findByApplicationId(applicationId))
                .thenReturn(List.of(versionEntity("v1", "key", "secret", true)));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("sdk");

        tested.versions(applicationId, List.of(SharedSecretAlgorithm.EC_P256));

        verify(sdkConfigurationSerializer).serialize(argThat(config ->
                "v3-p256-key".equals(config.masterPublicKeyP256())
        ));
    }

    @Test
    void versions_shouldOmitP256KeyFromSdkConfig_whenEc256IsNotSupported() throws GenericServiceException {
        final String applicationId = "app-no-p256-sdk";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-key"));

        when(applicationVersionRepository.findByApplicationId(applicationId))
                .thenReturn(List.of(versionEntity("v1", "key", "secret", true)));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("sdk");

        tested.versions(applicationId, List.of(SharedSecretAlgorithm.EC_P384));

        verify(sdkConfigurationSerializer).serialize(argThat(config ->
                config.masterPublicKeyP256() == null
        ));
    }

    @Test
    void versions_shouldCallSerializerOncePerVersion() throws GenericServiceException {
        final String applicationId = "app-three-versions";
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(keyPairWithV3Key(applicationId, "v3-key"));

        when(applicationVersionRepository.findByApplicationId(applicationId)).thenReturn(List.of(
                versionEntity("v1", "key-1", "secret-1", true),
                versionEntity("v2", "key-2", "secret-2", true),
                versionEntity("v3", "key-3", "secret-3", false)
        ));
        when(sdkConfigurationSerializer.serialize(any())).thenReturn("sdk");

        tested.versions(applicationId, List.of());

        verify(sdkConfigurationSerializer, times(3)).serialize(any());
    }

    @Test
    void versions_shouldThrowGenericServiceException_whenNoKeyPairFound() throws GenericServiceException {
        final String applicationId = "app-missing-keys";
        final GenericServiceException expected =
                new GenericServiceException(ServiceError.NO_MASTER_SERVER_KEYPAIR, "No key pair");

        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId))
                .thenReturn(null);
        when(localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR)).thenReturn(expected);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.versions(applicationId, List.of())
        );
        assertSame(expected, thrown);
        verifyNoInteractions(applicationVersionRepository);
        verifyNoInteractions(sdkConfigurationSerializer);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ApplicationEntity applicationEntity(String applicationId) {
        final ApplicationEntity entity = new ApplicationEntity();
        entity.setId(applicationId);
        return entity;
    }

    private static MasterKeyPairEntity keyPairWithV3Key(String applicationId, String publicKeyBase64) {
        final ApplicationEntity application = applicationEntity(applicationId);
        final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
        keyPair.setApplication(application);
        keyPair.setMasterKeyPublicBase64(publicKeyBase64);
        return keyPair;
    }

    private static ApplicationVersionEntity versionEntity(String id, String appKey, String appSecret, boolean supported) {
        final ApplicationVersionEntity entity = new ApplicationVersionEntity();
        entity.setId(id);
        entity.setApplicationKey(appKey);
        entity.setApplicationSecret(appSecret);
        entity.setSupported(supported);
        return entity;
    }

}
