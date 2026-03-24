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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

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
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfiguration;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfigurationException;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfigurationSerializer;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Behavior class implementing application detail endpoint.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("applicationDetailServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class ApplicationDetailServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ApplicationRepository applicationRepository;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final AlgorithmQueryService algorithmQueryService;
    private final MasterPublicKeyService masterPublicKeyService;
    /**
     * Get application details by ID.
     *
     * @param request Request with application ID
     * @return Response with application details
     * @throws GenericServiceException Thrown when application does not exist.
     */
    @Transactional
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final ApplicationEntity application = findApplicationById(applicationId);
            return createApplicationDetailResponse(application);
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    private GetApplicationDetailResponse createApplicationDetailResponse(ApplicationEntity application) throws GenericServiceException {
        final String applicationId = application.getId();
        final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPairEntity == null) {
            // This can happen only when an application was not created properly using PA Server service
            logger.error("Missing key pair for application ID: {}", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
        final List<SharedSecretAlgorithm> supportedAlgorithms = algorithmQueryService.getSupportedAlgorithms(application);
        final MasterPublicKeys masterPublicKeys = masterPublicKeyService.extractPublicKeys(masterKeyPairEntity, supportedAlgorithms);

        try {
            final GetApplicationDetailResponse response = new GetApplicationDetailResponse();
            response.setApplicationId(applicationId);
            response.getApplicationRoles().addAll(application.getRoles());
            response.getSupportedAlgorithms().addAll(supportedAlgorithms.stream().map(SharedSecretAlgorithm::name).toList());

            final List<ApplicationVersionEntity> versions = applicationVersionRepository.findByApplicationId(applicationId);
            for (ApplicationVersionEntity version : versions) {
                final SdkConfiguration sdkConfig = SdkConfiguration.builder()
                        .appKey(version.getApplicationKey())
                        .appSecret(version.getApplicationSecret())
                        .masterPublicKeyP256(masterPublicKeys.p256())
                        .masterPublicKeyP384(masterPublicKeys.p384())
                        .masterPublicKeyMlDsa65(masterPublicKeys.mlDsa65())
                        .masterPublicKeyMlDsa87(masterPublicKeys.mlDsa87())
                        .build();
                final String sdkConfigSerialized = SdkConfigurationSerializer.serialize(sdkConfig);

                final ApplicationVersion ver = new ApplicationVersion();
                ver.setApplicationVersionId(version.getId());
                ver.setApplicationKey(version.getApplicationKey());
                ver.setApplicationSecret(version.getApplicationSecret());
                ver.setMobileSdkConfig(sdkConfigSerialized);
                ver.setSupported(version.getSupported());

                response.getVersions().add(ver);
            }
            return response;
        } catch (SdkConfigurationException exception) {
            logger.warn(exception.getMessage(), exception);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
    }

    /**
     * Find application entity by ID.
     * @param applicationId Application ID.
     * @return Application entity.
     * @throws GenericServiceException Thrown when application does not exist.
     */
    private ApplicationEntity findApplicationById(String applicationId) throws GenericServiceException {
        final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
        if (applicationOptional.isEmpty()) {
            logger.info("Application not found, application ID: '{}'", applicationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        return applicationOptional.get();
    }

}
