/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmQueryService;
import com.wultra.security.powerauth.app.server.service.crypto.MasterKeyGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.entity.Application;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Behavior class implementing the application management related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class ApplicationServiceBehavior extends AbstractApplicationServiceBehavior {

    @Autowired
    private MasterKeyGenerationService masterKeyGenerationService;
    @Autowired
    private LocalizationProvider localizationProvider;
    @Autowired
    private ApplicationRepository applicationRepository;
    @Autowired
    private ApplicationVersionRepository applicationVersionRepository;
    @Autowired
    private AlgorithmQueryService algorithmQueryService;

    private final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Lookup application based on version app key.
     *
     * @param request Request with application version key (APP_KEY).
     * @return Response with application details
     * @throws GenericServiceException Thrown when application does not exist.
     */
    @Transactional
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws GenericServiceException {
        try {
            final String applicationKey = request.getApplicationKey();
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersion == null) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final ApplicationEntity application = findApplicationById(applicationVersion.getApplication().getId());
            final LookupApplicationByAppKeyResponse response = new LookupApplicationByAppKeyResponse();
            response.setApplicationId(application.getId());
            return response;
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

    /**
     * Get application list in the PowerAuth Server instance.
     *
     * @return List of applications.
     */
    @Transactional
    public GetApplicationListResponse getApplicationList() throws GenericServiceException {
        try {
            final Iterable<ApplicationEntity> result = applicationRepository.findAll();

            final GetApplicationListResponse response = new GetApplicationListResponse();

            for (ApplicationEntity application : result) {
                final Application app = new Application();
                app.setApplicationId(application.getId());
                app.getApplicationRoles().addAll(application.getRoles());
                response.getApplications().add(app);
            }

            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Create a new application with given name.
     *
     * @param request Request with application ID
     * @return Response with new application information
     * @throws GenericServiceException In case cryptography provider is initialized incorrectly.
     */
    @Transactional
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();

            // Check application duplicity
            if (applicationRepository.findById(applicationId).isPresent()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.DUPLICATE_APPLICATION);
            }

            ApplicationEntity application = new ApplicationEntity();
            application.setId(applicationId);
            application = applicationRepository.save(application);

            // Generate master server key pairs
            final MasterKeyPairEntity keyPair = masterKeyGenerationService.generateAndSaveMasterKeyPairs(application);

            // Use cryptography methods before writing to database to avoid rollbacks
            final byte[] applicationKeyBytes = KEY_GENERATOR.generateRandomBytes(16);
            final byte[] applicationSecretBytes = KEY_GENERATOR.generateRandomBytes(16);

            // Create the default application version
            final ApplicationVersionEntity version = new ApplicationVersionEntity();
            version.setApplication(application);
            version.setId("default");
            version.setSupported(true);
            version.setApplicationKey(Base64.getEncoder().encodeToString(applicationKeyBytes));
            version.setApplicationSecret(Base64.getEncoder().encodeToString(applicationSecretBytes));
            applicationVersionRepository.save(version);

            final List<SharedSecretAlgorithm> supportedAlgorithms = algorithmQueryService.getSupportedAlgorithms(application);

            final CreateApplicationResponse response = new CreateApplicationResponse();
            response.setApplicationId(application.getId());
            response.getApplicationRoles().addAll(application.getRoles());
            response.getSupportedAlgorithms().addAll(supportedAlgorithms.stream().map(SharedSecretAlgorithm::name).toList());

            if (keyPair == null) {
                // This can happen only when an application was not created properly using PA Server service
                logger.error("Missing key pair for application ID: {}", applicationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            }
            final String publicKeyP256 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P256) ? keyPair.getMasterKeyPublicBase64() : null;

            final Result result = getPublicKeys(keyPair, publicKeyP256, supportedAlgorithms);
            final String sdkConfigSerialized = getSdkConfigSerialized(version, publicKeyP256, result);
            final ApplicationVersion ver = getApplicationVersion(version, sdkConfigSerialized);

            response.getVersions().add(ver);

            return response;
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, exception can be triggered only before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
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

    /**
     * Create a new application version
     *
     * @param request Request with application ID and version name.
     * @return Response with new version information
     * @throws GenericServiceException Thrown when application does not exist.
     */
    @Transactional
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws GenericServiceException {
        try {
            logger.info("CreateApplicationVersionRequest received: {}", request);
            final String applicationId = request.getApplicationId();
            final String applicationVersionId = request.getApplicationVersionId();

            final ApplicationEntity application = findApplicationById(applicationId);

            // Check for duplicate application
            for (ApplicationVersionEntity applicationVersionEntity : application.getVersions()) {
                final String applicationVersionEntityId = applicationVersionEntity.getId();
                if (applicationVersionEntityId != null && applicationVersionEntityId.equals(applicationVersionId)) {
                    logger.warn("Duplicate application version ID: {} for application ID: {}", applicationVersionId, applicationId);
                    throw localizationProvider.buildExceptionForCode(ServiceError.DUPLICATE_APPLICATION);
                }
            }

            final KeyGenerator keyGen = new KeyGenerator();
            final byte[] applicationKeyBytes;
            final byte[] applicationSecretBytes;
            try {
                applicationKeyBytes = keyGen.generateRandomBytes(16);
                applicationSecretBytes = keyGen.generateRandomBytes(16);
            } catch (CryptoProviderException ex) {
                logger.error(ex.getMessage(), ex);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
            }

            ApplicationVersionEntity version = new ApplicationVersionEntity();
            version.setApplication(application);
            version.setId(applicationVersionId);
            version.setSupported(true);
            version.setApplicationKey(Base64.getEncoder().encodeToString(applicationKeyBytes));
            version.setApplicationSecret(Base64.getEncoder().encodeToString(applicationSecretBytes));
            version = applicationVersionRepository.save(version);

            final CreateApplicationVersionResponse response = new CreateApplicationVersionResponse();
            response.setApplicationVersionId(version.getId());
            response.setApplicationKey(version.getApplicationKey());
            response.setApplicationSecret(version.getApplicationSecret());
            response.setSupported(version.getSupported());

            logger.info("CreateApplicationVersionRequest succeeded");
            return response;
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

    /**
     * Mark a version with given ID as unsupported
     *
     * @param request Request with app ID and app version ID.
     * @return Response confirming the operation
     * @throws GenericServiceException Thrown when application version does not exist.
     */
    @Transactional
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws GenericServiceException {
        try {
            logger.info("UnsupportApplicationVersionRequest received: {}", request);
            final String applicationId = request.getApplicationId();
            final String applicationVersionId = request.getApplicationVersionId();
            ApplicationVersionEntity version = findApplicationVersion(applicationId, applicationVersionId);
            version.setSupported(false);
            version = applicationVersionRepository.save(version);

            final UnsupportApplicationVersionResponse response = new UnsupportApplicationVersionResponse();
            response.setApplicationVersionId(version.getId());
            response.setSupported(version.getSupported());

            logger.info("UnsupportApplicationVersionRequest succeeded");
            return response;
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

    /**
     * Mark a version with given ID as supported
     *
     * @param request Request with app ID and app version ID.
     * @return Response confirming the operation
     * @throws GenericServiceException Thrown when application version does not exist.
     */
    @Transactional
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws GenericServiceException {
        try {
            logger.info("SupportApplicationVersionRequest received: {}", request);
            final String applicationId = request.getApplicationId();
            final String applicationVersionId = request.getApplicationVersionId();
            ApplicationVersionEntity version = findApplicationVersion(applicationId, applicationVersionId);

            version.setSupported(true);
            version = applicationVersionRepository.save(version);

            final SupportApplicationVersionResponse response = new SupportApplicationVersionResponse();
            response.setApplicationVersionId(version.getId());
            response.setSupported(version.getSupported());

            logger.info("SupportApplicationVersionRequest succeeded");
            return response;
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

    /**
     * Find application version entity by ID.
     * @param appId Application ID.
     * @param versionId Application version ID.
     * @return Application version entity.
     * @throws GenericServiceException Thrown when application version does not exist.
     */
    private ApplicationVersionEntity findApplicationVersion(String appId, String versionId) throws GenericServiceException {
        final Optional<ApplicationVersionEntity> applicationVersionOptional = applicationVersionRepository.findFirstByApplicationIdAndName(appId, versionId);
        if (applicationVersionOptional.isEmpty()) {
            logger.info("Application version not found, application version ID: {}", versionId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        return applicationVersionOptional.get();
    }

}
