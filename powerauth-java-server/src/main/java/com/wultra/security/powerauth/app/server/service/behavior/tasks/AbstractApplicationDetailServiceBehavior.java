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
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmQueryService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.SdkConfiguration;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Abstract Behavior class implementing application detail endpoint
 * for all the subsequent version.
 *
 * @author Vít Kotačka, vit.kotacka@wultra.com
 */
public abstract class AbstractApplicationDetailServiceBehavior extends AbstractApplicationServiceBehavior {

    @Autowired
    private LocalizationProvider localizationProvider;
    @Autowired
    private ApplicationRepository applicationRepository;
    @Autowired
    private MasterKeyPairRepository masterKeyPairRepository;
    @Autowired
    private ApplicationVersionRepository applicationVersionRepository;
    @Autowired
    private AlgorithmQueryService algorithmQueryService;

    /**
     * Find application entity by ID.
     * @param applicationId Application ID.
     * @return Application entity.
     * @throws GenericServiceException Thrown when application does not exist.
     */
    protected ApplicationEntity findApplicationById(String applicationId) throws GenericServiceException {
        final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
        if (applicationOptional.isEmpty()) {
            logger.info("Application not found, application ID: '{}'", applicationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        return applicationOptional.get();
    }

    protected List<SharedSecretAlgorithm> supportedAlgorithms(ApplicationEntity application) {
        return algorithmQueryService.getSupportedAlgorithms(application);
    }

    protected List<ApplicationVersion> versions(String applicationId, List<SharedSecretAlgorithm> supportedAlgorithms, Result publicKeys) throws GenericServiceException {
        final List<ApplicationVersion> versions = new ArrayList<>();
        final List<ApplicationVersionEntity> entities = applicationVersionRepository.findByApplicationId(applicationId);
        for (ApplicationVersionEntity version : entities) {
            final String masterPublicKeyP256 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P256) ? publicKeys.publicKeyP256() : null;
            final String masterPublicKeyP384 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384) ? publicKeys.publicKeyP384() : null;
            final String masterPublicKeyMlDsa65 = supportedAlgorithms.contains(SharedSecretAlgorithm.ML_DSA_65) ? publicKeys.publicKeyMlDsa65() : null;
            final String masterPublicKeyMlDsa87 = supportedAlgorithms.contains(SharedSecretAlgorithm.ML_DSA_87) ? publicKeys.publicKeyMlDsa87() : null;

            final SdkConfiguration sdkConfig = SdkConfiguration.builder()
                    .appKey(version.getApplicationKey())
                    .appSecret(version.getApplicationSecret())
                    .masterPublicKeyP256(masterPublicKeyP256)
                    .masterPublicKeyP384(masterPublicKeyP384)
                    .masterPublicKeyMlDsa65(masterPublicKeyMlDsa65)
                    .masterPublicKeyMlDsa87(masterPublicKeyMlDsa87)
                    .build();
            final String sdkConfigSerialized = sdkConfigurationSerializer.serialize(sdkConfig);
            final ApplicationVersion ver = getApplicationVersion(version, sdkConfigSerialized);

            versions.add(ver);
        }

        return versions;
    }

    protected @NonNull Result getPublicKeys(String applicationId, List<SharedSecretAlgorithm> supportedAlgorithms) throws GenericServiceException {
        final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPairEntity == null) {
            // This can happen only when an application was not created properly using PA Server service
            logger.error("Missing key pair for application ID: {}", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }

        final String publicKeyP256 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P256) ? masterKeyPairEntity.getMasterKeyPublicBase64() : null;

        return super.getPublicKeys(masterKeyPairEntity, publicKeyP256, supportedAlgorithms);
    }
}