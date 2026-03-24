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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmQueryService;
import com.wultra.security.powerauth.app.server.database.model.MasterPublicKeys;
import com.wultra.security.powerauth.app.server.service.crypto.MasterPublicKeyService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.v3.GetApplicationDetailResponse;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfiguration;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfigurationSerializer;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for v3 {@link com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.ApplicationDetailServiceBehavior}.
 *
 * @author Vit Kotacka, vit.kotacka@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ApplicationDetailServiceBehaviorTest {

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
    private MasterPublicKeyService masterPublicKeyService;

    @InjectMocks
    private ApplicationDetailServiceBehavior applicationDetailServiceBehavior;

    private static final String KEY_P256   = Base64.getEncoder().encodeToString("my-p256-key".getBytes());
    private static final String APP_KEY    = Base64.getEncoder().encodeToString("app-key".getBytes());
    private static final String APP_SECRET = Base64.getEncoder().encodeToString("app-secret".getBytes());

    @BeforeEach
    void stubMasterPublicKeyService() throws Exception {
        // lenient: not needed in tests that fail before key extraction (e.g. missing app, missing key pair)
        lenient().when(masterPublicKeyService.extractPublicKeys(any(), any()))
                .thenReturn(new MasterPublicKeys(KEY_P256, null, null, null));
    }

    @Test
    void getApplicationDetail_shouldThrowException_whenApplicationNotFound() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("missing-app");

        when(applicationRepository.findById("missing-app")).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_APPLICATION, "Not found"));

        assertThrows(GenericServiceException.class, () -> applicationDetailServiceBehavior.getApplicationDetail(request));
        verifyNoInteractions(masterKeyPairRepository);
    }

    @Test
    void getApplicationDetail_shouldThrowException_whenMasterKeyPairMissing() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(null);
        when(localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR))
                .thenReturn(new GenericServiceException(ServiceError.NO_MASTER_SERVER_KEYPAIR, "No key pair"));

        assertThrows(GenericServiceException.class, () -> applicationDetailServiceBehavior.getApplicationDetail(request));
    }

    @Test
    void getApplicationDetail_shouldReturnResponseWithApplicationId_whenSucceeds() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of());

        final GetApplicationDetailResponse response = applicationDetailServiceBehavior.getApplicationDetail(request);

        assertNotNull(response);
        assertEquals("app-1", response.getApplicationId());
    }

    @Test
    void getApplicationDetail_shouldIncludeApplicationRoles_whenSet() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        application.getRoles().addAll(List.of("ROLE_A", "ROLE_B"));
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of());

        final GetApplicationDetailResponse response = applicationDetailServiceBehavior.getApplicationDetail(request);

        assertEquals(List.of("ROLE_A", "ROLE_B"), response.getApplicationRoles());
    }

    @Test
    void getApplicationDetail_shouldSetMasterPublicKey_whenEC_P256Supported() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));
        when(masterPublicKeyService.extractPublicKeys(any(), any()))
                .thenReturn(new MasterPublicKeys(KEY_P256, null, null, null));
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of());

        final GetApplicationDetailResponse response = applicationDetailServiceBehavior.getApplicationDetail(request);

        assertEquals(KEY_P256, response.getMasterPublicKey());
    }

    @Test
    void getApplicationDetail_shouldSetNullMasterPublicKey_whenEC_P256NotSupported() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());
        when(masterPublicKeyService.extractPublicKeys(any(), any()))
                .thenReturn(new MasterPublicKeys(null, null, null, null));
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of());

        final GetApplicationDetailResponse response = applicationDetailServiceBehavior.getApplicationDetail(request);

        assertNull(response.getMasterPublicKey());
    }

    @Test
    void getApplicationDetail_shouldSetNullPublicKeyP256_whenEC_P256NotSupported() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());
        when(masterPublicKeyService.extractPublicKeys(any(), any()))
                .thenReturn(new MasterPublicKeys(null, null, null, null));

        final ApplicationVersionEntity version = versionEntity("v1", APP_KEY, APP_SECRET, true);
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of(version));

        final var applicationDetail = applicationDetailServiceBehavior.getApplicationDetail(request);
        assertEquals(1, applicationDetail.getVersions().size());
        final var sdkConfig = SdkConfiguration.builder()
                .appKey(APP_KEY)
                .appSecret(APP_SECRET)
                .build();
        assertEquals(SdkConfigurationSerializer.serialize(sdkConfig), applicationDetail.getVersions().get(0).getMobileSdkConfig());
    }

    @Test
    void getApplicationDetail_shouldSetNullP384Keys_whenMasterPublicKeysIsNull() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application))
                .thenReturn(List.of(SharedSecretAlgorithm.EC_P256, SharedSecretAlgorithm.EC_P384,
                        SharedSecretAlgorithm.EC_P384_ML_L3, SharedSecretAlgorithm.EC_P384_ML_L5));

        final ApplicationVersionEntity version = versionEntity("v1", APP_KEY, APP_SECRET, true);
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of(version));

        final var applicationDetail = applicationDetailServiceBehavior.getApplicationDetail(request);
        assertEquals(1, applicationDetail.getVersions().size());
        final var sdkConfig = SdkConfiguration.builder()
                .appKey(APP_KEY)
                .appSecret(APP_SECRET)
                .masterPublicKeyP256(KEY_P256)
                .build();
        assertEquals(SdkConfigurationSerializer.serialize(sdkConfig), applicationDetail.getVersions().get(0).getMobileSdkConfig());
    }

    @Test
    void getApplicationDetail_shouldSetNullP384Keys_whenMasterPublicKeysHasNoMatchingKeys() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, "{}");
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application))
                .thenReturn(List.of(SharedSecretAlgorithm.EC_P384, SharedSecretAlgorithm.EC_P384_ML_L3, SharedSecretAlgorithm.EC_P384_ML_L5));
        when(masterPublicKeyService.extractPublicKeys(any(), any()))
                .thenReturn(new MasterPublicKeys(null, null, null, null));

        final ApplicationVersionEntity version = versionEntity("v1", APP_KEY, APP_SECRET, true);
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of(version));

        final var applicationDetail = applicationDetailServiceBehavior.getApplicationDetail(request);
        assertEquals(1, applicationDetail.getVersions().size());
        final var sdkConfig = SdkConfiguration.builder()
                .appKey(APP_KEY)
                .appSecret(APP_SECRET)
                .build();
        assertEquals(SdkConfigurationSerializer.serialize(sdkConfig), applicationDetail.getVersions().get(0).getMobileSdkConfig());
    }

    @Test
    void getApplicationDetail_shouldMapVersionFields_correctly() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of(SharedSecretAlgorithm.EC_P256));

        final ApplicationVersionEntity version = versionEntity("default", APP_KEY, APP_SECRET, true);
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of(version));

        final GetApplicationDetailResponse response = applicationDetailServiceBehavior.getApplicationDetail(request);
        assertEquals(1, response.getVersions().size());
        final ApplicationVersion ver = response.getVersions().get(0);
        assertEquals("default", ver.getApplicationVersionId());
        assertEquals(APP_KEY, ver.getApplicationKey());
        assertEquals(APP_SECRET, ver.getApplicationSecret());
        assertTrue(ver.isSupported());

        final var sdkConfig = SdkConfiguration.builder()
                .appKey(APP_KEY)
                .appSecret(APP_SECRET)
                .masterPublicKeyP256(KEY_P256)
                .build();
        assertEquals(SdkConfigurationSerializer.serialize(sdkConfig), ver.getMobileSdkConfig());
    }

    @Test
    void getApplicationDetail_shouldReturnEmptyVersions_whenNoVersionsExist() throws Exception {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of());

        final GetApplicationDetailResponse response = applicationDetailServiceBehavior.getApplicationDetail(request);

        assertTrue(response.getVersions().isEmpty());
    }

    @Test
    void getApplicationDetail_shouldPropagateRuntimeException() {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        when(applicationRepository.findById("app-1")).thenThrow(new RuntimeException("DB error"));

        assertThrows(RuntimeException.class, () -> applicationDetailServiceBehavior.getApplicationDetail(request));
    }

    @Test
    void getApplicationDetail_shouldThrowInvalidApplication_whenAppKeyIsMissing() {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId("app-1");

        final ApplicationEntity application = applicationEntity("app-1");
        final MasterKeyPairEntity keyPair = keyPairEntity(KEY_P256, null);
        when(applicationRepository.findById("app-1")).thenReturn(Optional.of(application));
        when(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc("app-1")).thenReturn(keyPair);
        when(algorithmQueryService.getSupportedAlgorithms(application)).thenReturn(List.of());

        // Trigger SdkConfigurationException by passing null appKey
        final ApplicationVersionEntity version = versionEntity("v1", null, APP_SECRET, true);
        when(applicationVersionRepository.findByApplicationId("app-1")).thenReturn(List.of(version));

        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_APPLICATION, "Invalid application."));

        final GenericServiceException ex = assertThrows(GenericServiceException.class,
                () -> applicationDetailServiceBehavior.getApplicationDetail(request));
        assertEquals(ServiceError.INVALID_APPLICATION, ex.getCode());
    }

    // --- helpers ---

    private static ApplicationEntity applicationEntity(String id) {
        final ApplicationEntity entity = new ApplicationEntity();
        entity.setId(id);
        return entity;
    }

    private static MasterKeyPairEntity keyPairEntity(String publicKeyP256, String masterPublicKeys) {
        final MasterKeyPairEntity entity = new MasterKeyPairEntity();
        entity.setMasterKeyPublicBase64(publicKeyP256);
        entity.setMasterPublicKeys(masterPublicKeys);
        return entity;
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
