/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Behavior class implementing the application management related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class ApplicationServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(ApplicationServiceBehavior.class);

    @Autowired
    public ApplicationServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
    }

    /**
     * Get application details by ID.
     *
     * @param applicationId Application ID
     * @return Response with application details
     * @throws GenericServiceException Thrown when application does not exist.
     */
    public GetApplicationDetailResponse getApplicationDetail(String applicationId) throws GenericServiceException {
        final ApplicationEntity application = findApplicationById(applicationId);
        return createApplicationDetailResponse(application);
    }

    private GetApplicationDetailResponse createApplicationDetailResponse(ApplicationEntity application) throws GenericServiceException {
        final String applicationId = application.getId();
        final MasterKeyPairEntity masterKeyPairEntity = repositoryCatalogue.getMasterKeyPairRepository().findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPairEntity == null) {
            // This can happen only when an application was not created properly using PA Server service
            logger.error("Missing key pair for application ID: {}", applicationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
        final GetApplicationDetailResponse response = new GetApplicationDetailResponse();
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(application.getRoles());
        response.setMasterPublicKey(masterKeyPairEntity.getMasterKeyPublicBase64());

        final List<ApplicationVersionEntity> versions = repositoryCatalogue.getApplicationVersionRepository().findByApplicationId(applicationId);
        for (ApplicationVersionEntity version : versions) {

            final GetApplicationDetailResponse.Versions ver = new GetApplicationDetailResponse.Versions();
            ver.setApplicationVersionId(version.getId());
            ver.setApplicationKey(version.getApplicationKey());
            ver.setApplicationSecret(version.getApplicationSecret());
            ver.setApplicationVersionId(version.getId());
            ver.setSupported(version.getSupported());

            response.getVersions().add(ver);
        }

        return response;
    }

    /**
     * Lookup application based on version app key.
     *
     * @param appKey Application version key (APP_KEY).
     * @return Response with application details
     * @throws GenericServiceException Thrown when application does not exist.
     */
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String appKey) throws GenericServiceException {
        final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(appKey);
        if (applicationVersion == null) {
            logger.warn("Application version is incorrect, application key: {}", appKey);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        final ApplicationEntity application = findApplicationById(applicationVersion.getApplication().getId());
        final LookupApplicationByAppKeyResponse response = new LookupApplicationByAppKeyResponse();
        response.setApplicationId(application.getId());
        return response;
    }

    /**
     * Get application list in the PowerAuth Server instance.
     *
     * @return List of applications.
     */
    public GetApplicationListResponse getApplicationList() {

        final Iterable<ApplicationEntity> result = repositoryCatalogue.getApplicationRepository().findAll();

        final GetApplicationListResponse response = new GetApplicationListResponse();

        for (ApplicationEntity application : result) {
            final GetApplicationListResponse.Applications app = new GetApplicationListResponse.Applications();
            app.setApplicationId(application.getId());
            app.getApplicationRoles().addAll(application.getRoles());
            response.getApplications().add(app);
        }

        return response;
    }

    /**
     * Create a new application with given name.
     *
     * @param id Application ID
     * @param keyConversionUtilities Utility class for the key conversion
     * @return Response with new application information
     * @throws GenericServiceException In case cryptography provider is initialized incorrectly.
     */
    public CreateApplicationResponse createApplication(String id, KeyConvertor keyConversionUtilities) throws GenericServiceException {
        try {
            // Check application duplicity
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            if (applicationRepository.findById(id).isPresent()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.DUPLICATE_APPLICATION);
            }

            ApplicationEntity application = new ApplicationEntity();
            application.setId(id);
            application = applicationRepository.save(application);

            final KeyGenerator keyGen = new KeyGenerator();
            final KeyPair kp = keyGen.generateKeyPair();
            final PrivateKey privateKey = kp.getPrivate();
            final PublicKey publicKey = kp.getPublic();

            // Use cryptography methods before writing to database to avoid rollbacks
            final byte[] applicationKeyBytes = keyGen.generateRandomBytes(16);
            final byte[] applicationSecretBytes = keyGen.generateRandomBytes(16);

            // Generate the default master key pair
            final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
            keyPair.setApplication(application);
            keyPair.setMasterKeyPrivateBase64(Base64.getEncoder().encodeToString(keyConversionUtilities.convertPrivateKeyToBytes(privateKey)));
            keyPair.setMasterKeyPublicBase64(Base64.getEncoder().encodeToString(keyConversionUtilities.convertPublicKeyToBytes(publicKey)));
            keyPair.setTimestampCreated(new Date());
            keyPair.setName(id + " Default Keypair");
            repositoryCatalogue.getMasterKeyPairRepository().save(keyPair);

            // Create the default application version
            final ApplicationVersionEntity version = new ApplicationVersionEntity();
            version.setApplication(application);
            version.setId("default");
            version.setSupported(true);
            version.setApplicationKey(Base64.getEncoder().encodeToString(applicationKeyBytes));
            version.setApplicationSecret(Base64.getEncoder().encodeToString(applicationSecretBytes));
            repositoryCatalogue.getApplicationVersionRepository().save(version);

            final CreateApplicationResponse response = new CreateApplicationResponse();
            response.setApplicationId(application.getId());

            return response;
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, exception can be triggered only before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Create a new application version
     *
     * @param applicationId Application ID
     * @param applicationVersionId   Application version ID
     * @return Response with new version information
     * @throws GenericServiceException Thrown when application does not exist.
     */
    public CreateApplicationVersionResponse createApplicationVersion(String applicationId, String applicationVersionId) throws GenericServiceException {

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
        version = repositoryCatalogue.getApplicationVersionRepository().save(version);

        final CreateApplicationVersionResponse response = new CreateApplicationVersionResponse();
        response.setApplicationVersionId(version.getId());
        response.setApplicationVersionId(version.getId());
        response.setApplicationKey(version.getApplicationKey());
        response.setApplicationSecret(version.getApplicationSecret());
        response.setSupported(version.getSupported());

        return response;
    }

    /**
     * Mark a version with given ID as unsupported
     *
     * @param appId Application ID.
     * @param versionId Version ID
     * @return Response confirming the operation
     * @throws GenericServiceException Thrown when application version does not exist.
     */
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(String appId, String versionId) throws GenericServiceException {

        ApplicationVersionEntity version = findApplicationVersion(appId, versionId);

        version.setSupported(false);
        version = repositoryCatalogue.getApplicationVersionRepository().save(version);

        final UnsupportApplicationVersionResponse response = new UnsupportApplicationVersionResponse();
        response.setApplicationVersionId(version.getId());
        response.setSupported(version.getSupported());

        return response;
    }

    /**
     * Mark a version with given ID as supported
     *
     * @param appId Application ID.
     * @param versionId Version ID
     * @return Response confirming the operation
     * @throws GenericServiceException Thrown when application version does not exist.
     */
    public SupportApplicationVersionResponse supportApplicationVersion(String appId, String versionId) throws GenericServiceException {

        ApplicationVersionEntity version = findApplicationVersion(appId, versionId);

        version.setSupported(true);
        version = repositoryCatalogue.getApplicationVersionRepository().save(version);

        final SupportApplicationVersionResponse response = new SupportApplicationVersionResponse();
        response.setApplicationVersionId(version.getId());
        response.setSupported(version.getSupported());

        return response;
    }

    /**
     * Find application entity by ID.
     * @param applicationId Application ID.
     * @return Application entity.
     * @throws GenericServiceException Thrown when application does not exist.
     */
    private ApplicationEntity findApplicationById(String applicationId) throws GenericServiceException {
        final Optional<ApplicationEntity> applicationOptional = repositoryCatalogue.getApplicationRepository().findById(applicationId);
        if (!applicationOptional.isPresent()) {
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
        final Optional<ApplicationVersionEntity> applicationVersionOptional = repositoryCatalogue.getApplicationVersionRepository().findFirstByApplicationIdAndName(appId, versionId);
        if (!applicationVersionOptional.isPresent()) {
            logger.info("Application version not found, application version ID: {}", versionId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        return applicationVersionOptional.get();
    }

}
