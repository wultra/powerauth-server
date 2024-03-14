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

package io.getlime.security.powerauth.app.server.service.fido2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
import com.wultra.powerauth.fido2.service.provider.AuthenticatorProvider;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.response.GetActivationListForUserResponse;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.client.model.enumeration.Protocols;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.AuditingServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * Authenticator provider based on PowerAuth activations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class PowerAuthAuthenticatorProvider implements AuthenticatorProvider {

    private static final String AUDIT_TYPE_FIDO2 = "fido2";

    private final ApplicationRepository applicationRepository;

    private final RepositoryCatalogue repositoryCatalogue;
    private final ServiceBehaviorCatalogue serviceBehaviorCatalogue;
    private final AuditingServiceBehavior audit;

    private LocalizationProvider localizationProvider;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    @Autowired
    public PowerAuthAuthenticatorProvider(RepositoryCatalogue repositoryCatalogue, ServiceBehaviorCatalogue serviceBehaviorCatalogue,
                                          ApplicationRepository applicationRepository, AuditingServiceBehavior audit) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.serviceBehaviorCatalogue = serviceBehaviorCatalogue;
        this.applicationRepository = applicationRepository;
        this.audit = audit;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    @Override
    @Transactional(readOnly = true)
    public List<AuthenticatorDetail> findByUserId(String userId, String applicationId) throws Fido2AuthenticationFailedException {

        // Find application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (application.isEmpty()) {
            logger.warn("Application with given ID is not present: {}", applicationId);
            throw new Fido2AuthenticationFailedException("Application with given ID is not present: " + applicationId);
        }

        final List<AuthenticatorDetail> authenticatorDetailList = new ArrayList<>();

        int pageIndex = 0;
        GetActivationListForUserResponse activationList = serviceBehaviorCatalogue.getActivationServiceBehavior().getActivationList(applicationId, userId, Set.of(Protocols.FIDO2), PageRequest.of(pageIndex, 1000), Set.of(ActivationStatus.ACTIVE, ActivationStatus.BLOCKED));
        while (!activationList.getActivations().isEmpty()) {
            for (Activation activation : activationList.getActivations()) {
                if (!Protocols.FIDO2.toString().equals(activation.getProtocol())) { // Check the protocol, just in case
                    continue;
                }
                final Optional<AuthenticatorDetail> authenticatorOptional = convert(activation, application.get());
                authenticatorOptional.ifPresent(authenticatorDetailList::add);
            }
            pageIndex++;
            activationList = serviceBehaviorCatalogue.getActivationServiceBehavior().getActivationList(applicationId, userId, Set.of(Protocols.FIDO2), PageRequest.of(pageIndex, 1000), Set.of(ActivationStatus.ACTIVE, ActivationStatus.BLOCKED));
        }
        return authenticatorDetailList;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<AuthenticatorDetail> findByCredentialId(String credentialId, String applicationId) throws Fido2AuthenticationFailedException {

        // Find application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (application.isEmpty()) {
            logger.warn("Application with given ID is not present: {}", applicationId);
            throw new Fido2AuthenticationFailedException("Application with given ID is not present: " + applicationId);
        }

        final List<Activation> activationRecordEntities = serviceBehaviorCatalogue.getActivationServiceBehavior().findByExternalId(applicationId, credentialId);
        if (activationRecordEntities == null || activationRecordEntities.size() != 1) {
            throw new Fido2AuthenticationFailedException("Two authenticators with the same ID exist - ambiguous result.");
        }
        final Activation activation = activationRecordEntities.get(0);

        return convert(activation, application.get());
    }

    @Override
    @Transactional
    public AuthenticatorDetail storeAuthenticator(String applicationId, String activationCode, AuthenticatorDetail authenticatorDetail) throws Fido2AuthenticationFailedException {

        try {
            // Get current timestamp
            final Date timestamp = new Date();

            // Get required repositories
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

            // Find application
            final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
            if (application.isEmpty()) {
                logger.warn("Application with given ID is not present: {}", applicationId);
                throw new Fido2AuthenticationFailedException("Application with given ID is not present: " + applicationId);
            }
            final ApplicationEntity applicationEntity = application.get();

            // Fetch the current activation by activation code
            final Set<io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus> states = Set.of(io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.CREATED);
            // Search for activation without lock to avoid potential deadlocks
            ActivationRecordEntity activation = activationRepository.findCreatedActivationWithoutLock(applicationId, activationCode, states, timestamp);

            // Check if the activation exists
            if (activation == null) {
                logger.warn("Activation with activation code: {} could not be obtained. It either does not exist or it already expired.", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Make sure this is the FIDO2 authenticator
            if (!Protocols.FIDO2.toString().equals(activation.getProtocol())) {
                logger.warn("Invalid authenticator protocol, expected 'fido2', obtained: {}", activation.getProtocol());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Search for activation again to acquire PESSIMISTIC_WRITE lock for activation row
            activation = activationRepository.findActivationWithLock(activation.getActivationId());
            deactivatePendingActivation(timestamp, activation);

            // Validate that the activation is in correct state for the prepare step
            validateCreatedActivation(activation, applicationEntity);

            // Extract the device public key from request
            final byte[] devicePublicKeyBytes = authenticatorDetail.getPublicKeyBytes();
            PublicKey devicePublicKey = null;
            try {
                devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                logger.warn("Invalid public key, activation ID: {}, {}", activation.getActivationId(), ex.getMessage());
                logger.debug("Invalid public key, activation ID: {}", activation.getActivationId(), ex);
                handleInvalidPublicKey(activation);
            }

            // Initialize hash based counter
            final HashBasedCounter counter = new HashBasedCounter();
            final byte[] ctrData = counter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

            // Update the activation record
            activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.ACTIVE);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(authenticatorDetail.getActivationName());
            activation.setExternalId(authenticatorDetail.getCredentialId());
            activation.setExtras(objectMapper.writeValueAsString(authenticatorDetail.getExtras()));
            if (authenticatorDetail.getPlatform() != null) {
                activation.setPlatform(authenticatorDetail.getPlatform().toLowerCase());
            } else {
                activation.setPlatform("unknown");
            }
            activation.setDeviceInfo(authenticatorDetail.getDeviceInfo());
            // PowerAuth protocol version 3.0 uses 0x3 as version in activation status
            activation.setVersion(3);
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);

            // Persist activation report and notify listeners
            serviceBehaviorCatalogue.getActivationHistoryServiceBehavior().saveActivationAndLogChange(activation);
            serviceBehaviorCatalogue.getCallbackUrlBehavior().notifyCallbackListenersOnActivationChange(activation);

            final Activation activationResponse = new Activation();
            activationResponse.setActivationId(activation.getActivationId());
            activationResponse.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            activationResponse.setBlockedReason(activation.getBlockedReason());
            activationResponse.setExternalId(activation.getExternalId());
            activationResponse.setActivationName(activation.getActivationName());
            activationResponse.setExtras(activation.getExtras());
            activationResponse.setPlatform(activation.getPlatform());
            activationResponse.setDeviceInfo(activation.getDeviceInfo());
            activationResponse.getActivationFlags().addAll(activation.getFlags());
            activationResponse.setTimestampCreated(activation.getTimestampCreated());
            activationResponse.setTimestampLastUsed(activation.getTimestampLastUsed());
            activationResponse.setTimestampLastChange(activation.getTimestampLastChange());
            activationResponse.setUserId(activation.getUserId());
            activationResponse.setApplicationId(activation.getApplication().getId());
            // Unknown version is converted to 0 in service
            activationResponse.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
            activationResponse.setFailedAttempts(activation.getFailedAttempts());
            activationResponse.setMaxFailedAttempts(activation.getMaxFailedAttempts());
            activationResponse.setDevicePublicKeyBase64(activation.getDevicePublicKeyBase64());

            auditStoredAuthenticator(activationResponse);

            // Generate authenticator detail
            final Optional<AuthenticatorDetail> authenticatorOptional = convert(activationResponse, applicationEntity);
            authenticatorOptional.orElseThrow(() -> new Fido2AuthenticationFailedException("Authenticator object deserialization failed"));
            return authenticatorOptional.get();
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw new Fido2AuthenticationFailedException("Generic cryptography error");
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw new Fido2AuthenticationFailedException("Invalid cryptography provider");
        } catch (JsonProcessingException e) {
            throw new Fido2AuthenticationFailedException("Unable to serialize extras");
        } catch (GenericServiceException e) {
            throw new Fido2AuthenticationFailedException("Generic service exception");
        }
    }

    /**
     * Audit stored authenticator for an activation.
     * @param activation Activation record.
     */
    private void auditStoredAuthenticator(Activation activation) {
        final AuditDetail auditDetail = AuditDetail.builder()
                .type(AUDIT_TYPE_FIDO2)
                .param("userId", activation.getUserId())
                .param("applicationId", activation.getApplicationId())
                .param("activationId", activation.getActivationId())
                .param("activationName", activation.getActivationName())
                .param("externalId", activation.getExternalId())
                .param("platform", activation.getPlatform())
                .param("deviceInfo", activation.getDeviceInfo())
                .build();
        audit.log(AuditLevel.INFO, "Stored authenticator for activation with ID: {}", auditDetail, activation.getActivationId());
    }

    private Optional<AuthenticatorDetail> convert(Activation activation, ApplicationEntity application) {
        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();

        authenticatorDetail.setApplicationId(activation.getApplicationId());
        authenticatorDetail.setUserId(activation.getUserId());
        authenticatorDetail.setActivationId(activation.getActivationId());
        authenticatorDetail.setActivationStatus(activation.getActivationStatus());
        authenticatorDetail.setActivationName(activation.getActivationName());
        authenticatorDetail.setCredentialId(activation.getExternalId());
        try {
            authenticatorDetail.setExtras(objectMapper.readValue(activation.getExtras(), new TypeReference<HashMap<String,Object>>() {}));
        } catch (JsonProcessingException e) {
            logger.warn(e.getMessage(), e);
            return Optional.empty();
        }
        authenticatorDetail.setActivationFlags(activation.getActivationFlags());
        authenticatorDetail.setDeviceInfo(activation.getDeviceInfo());
        authenticatorDetail.setPlatform(activation.getPlatform());
        authenticatorDetail.setFailedAttempts(activation.getFailedAttempts());
        authenticatorDetail.setMaxFailedAttempts(activation.getMaxFailedAttempts());
        authenticatorDetail.setBlockedReason(activation.getBlockedReason());
        if (activation.getDevicePublicKeyBase64() != null) {
            authenticatorDetail.setPublicKeyBytes(Base64.getDecoder().decode(activation.getDevicePublicKeyBase64()));
        }

        authenticatorDetail.setApplicationRoles(application.getRoles());

        return Optional.of(authenticatorDetail);
    }


    /**
     * Validate activation in prepare or create activation step: it should be in CREATED state, it should be linked to correct
     * application and the activation code should have valid length.
     *
     * @param activation  Activation used in prepare activation step.
     * @param application Application used in prepare activation step.
     * @throws GenericServiceException In case activation state is invalid.
     */
    private void validateCreatedActivation(ActivationRecordEntity activation, ApplicationEntity application) throws GenericServiceException {
        // If there is no such activation or application does not match the activation application, fail validation
        if (activation == null
                || !io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.CREATED.equals(activation.getActivationStatus())
                || !Objects.equals(activation.getApplication().getRid(), application.getRid())) {
            logger.info("Activation state is invalid, activation ID: {}", activation != null ? activation.getActivationId() : "unknown");
            // Regular exception is used during prepareActivation
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        // Make sure activation code has 23 characters
        if (activation.getActivationCode().length() != 23) {
            logger.warn("Activation code is invalid, activation ID: {}", activation.getActivationId());
            // Regular exception is used during prepareActivation
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }
    }

    /**
     * Deactivate the activation in CREATED or PENDING_COMMIT if it's activation expiration timestamp
     * is below the given timestamp.
     *
     * @param timestamp  Timestamp to check activations against.
     * @param activation Activation to check.
     */
    private void deactivatePendingActivation(Date timestamp, ActivationRecordEntity activation) {
        if ((activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.CREATED) || activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.PENDING_COMMIT))
                && (timestamp.getTime() > activation.getTimestampActivationExpire().getTime())) {
            logger.info("Deactivating pending activation, activation ID: {}", activation.getActivationId());
            removeActivationInternal(activation);
        }
    }

    /**
     * Internal logic for processing activation removal.
     *
     * @param activation Activation entity.
     */
    private void removeActivationInternal(final ActivationRecordEntity activation) {
        activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.REMOVED);
        // Recovery codes are revoked in case revocation is requested, or always when the activation is in CREATED or PENDING_COMMIT state
        serviceBehaviorCatalogue.getActivationHistoryServiceBehavior().saveActivationAndLogChange(activation, null);
        serviceBehaviorCatalogue.getCallbackUrlBehavior().notifyCallbackListenersOnActivationChange(activation);
    }

    /**
     * Handle case when public key is invalid. Remove provided activation (mark as REMOVED),
     * notify callback listeners, and throw an exception.
     *
     * @param activation Activation to be removed.
     * @throws GenericServiceException Error caused by invalid public key.
     */
    private void handleInvalidPublicKey(ActivationRecordEntity activation) throws GenericServiceException {
        activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.REMOVED);
        serviceBehaviorCatalogue.getActivationHistoryServiceBehavior().saveActivationAndLogChange(activation);
        serviceBehaviorCatalogue.getCallbackUrlBehavior().notifyCallbackListenersOnActivationChange(activation);
        // Exception must not be rollbacking, otherwise data written to database in this method would be lost
        throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
    }
}
