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

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.ApplicationDetailServiceBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmQueryService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.SdkConfiguration;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.util.SdkConfigurationSerializer;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.experimental.SuperBuilder;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Abstract Behavior class implementing application detail endpoint
 * for all the subsequent version.
 *
 * @author Vít Kotačka, vit.kotacka@wultra.com
 */
@SuperBuilder
public abstract class AbstractApplicationDetailServiceBehavior extends AbstractApplicationServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ApplicationRepository applicationRepository;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final AlgorithmQueryService algorithmQueryService;
    private final SdkConfigurationSerializer sdkConfigurationSerializer;

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
            ApplicationDetailServiceBehavior.logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            ApplicationDetailServiceBehavior.logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
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
            ApplicationDetailServiceBehavior.logger.info("Application not found, application ID: '{}'", applicationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        return applicationOptional.get();
    }

    private GetApplicationDetailResponse createApplicationDetailResponse(ApplicationEntity application) throws GenericServiceException {
        final String applicationId = application.getId();
        final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPairEntity == null) {
            // This can happen only when an application was not created properly using PA Server service
            ApplicationDetailServiceBehavior.logger.error("Missing key pair for application ID: {}", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
        final List<SharedSecretAlgorithm> supportedAlgorithms = algorithmQueryService.getSupportedAlgorithms(application);

        final String publicKeyP256 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P256) ? masterKeyPairEntity.getMasterKeyPublicBase64() : null;

        final Result result = getResult(masterKeyPairEntity, supportedAlgorithms);

        final GetApplicationDetailResponse response = new GetApplicationDetailResponse();
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(application.getRoles());
        response.getSupportedAlgorithms().addAll(supportedAlgorithms.stream().map(SharedSecretAlgorithm::name).toList());

        final List<ApplicationVersionEntity> versions = applicationVersionRepository.findByApplicationId(applicationId);
        for (ApplicationVersionEntity version : versions) {
            final SdkConfiguration sdkConfig = SdkConfiguration.builder()
                    .appKey(version.getApplicationKey())
                    .appSecret(version.getApplicationSecret())
                    .masterPublicKeyP256(publicKeyP256)
                    .masterPublicKeyP384(result.publicKeyP384())
                    .masterPublicKeyMlDsa65(result.publicKeyMlDsa65())
                    .masterPublicKeyMlDsa87(result.publicKeyMlDsa87())
                    .build();
            final String sdkConfigSerialized = sdkConfigurationSerializer.serialize(sdkConfig);

            final ApplicationVersion ver = getApplicationVersion(version, sdkConfigSerialized);

            response.getVersions().add(ver);
        }

        return response;
    }
}