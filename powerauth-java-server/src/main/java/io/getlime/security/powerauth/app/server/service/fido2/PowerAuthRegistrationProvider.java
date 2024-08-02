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

import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.converter.RegistrationChallengeConverter;
import com.wultra.powerauth.fido2.rest.model.entity.RegistrationChallenge;
import com.wultra.powerauth.fido2.service.provider.RegistrationProvider;
import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveActivationRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.fido2.model.entity.Credential;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.wultra.powerauth.fido2.rest.model.enumeration.Fido2ConfigKeys.CONFIG_KEY_ALLOWED_AAGUIDS;
import static com.wultra.powerauth.fido2.rest.model.enumeration.Fido2ConfigKeys.CONFIG_KEY_ALLOWED_ATTESTATION_FMT;

/**
 * Challenge provider based on the PowerAuth core implementations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class PowerAuthRegistrationProvider implements RegistrationProvider {

    private final RepositoryCatalogue repositoryCatalogue;
    private final PowerAuthAuthenticatorProvider authenticatorProvider;
    private final RegistrationChallengeConverter registrationChallengeConverter;

    private final ActivationServiceBehavior activations;
    private final ApplicationConfigServiceBehavior applicationConfig;
    private final ActivationQueryService activationQueryService;

    @Autowired
    public PowerAuthRegistrationProvider(final RepositoryCatalogue repositoryCatalogue, final PowerAuthAuthenticatorProvider authenticatorProvider, final RegistrationChallengeConverter registrationChallengeConverter, ActivationServiceBehavior activations, ApplicationConfigServiceBehavior applicationConfig, ActivationQueryService activationQueryService) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.authenticatorProvider = authenticatorProvider;
        this.registrationChallengeConverter = registrationChallengeConverter;
        this.activations = activations;
        this.applicationConfig = applicationConfig;
        this.activationQueryService = activationQueryService;
    }

    @Override
    @Transactional
    public RegistrationChallenge provideChallengeForRegistration(String userId, String applicationId) throws GenericServiceException, Fido2AuthenticationFailedException {
        final InitActivationRequest request = new InitActivationRequest();
        request.setProtocol(ActivationProtocol.FIDO2);
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setActivationOtpValidation(ActivationOtpValidation.NONE);
        final InitActivationResponse initActivationResponse = activations.initActivation(request);

        final List<Credential> excludeCredentials = authenticatorProvider.findByUserId(userId, applicationId)
                .stream()
                .map(registrationChallengeConverter::toCredentialDescriptor)
                .toList();

        final RegistrationChallenge registrationChallenge = new RegistrationChallenge();
        registrationChallenge.setUserId(initActivationResponse.getUserId());
        registrationChallenge.setApplicationId(initActivationResponse.getApplicationId());
        registrationChallenge.setActivationId(initActivationResponse.getActivationId());
        registrationChallenge.setChallenge(initActivationResponse.getActivationCode());
        registrationChallenge.setExcludeCredentials(excludeCredentials);
        return registrationChallenge;
    }

    @Override
    @Transactional(readOnly = true)
    public RegistrationChallenge findRegistrationChallengeByValue(String applicationId, String challengeValue) throws Fido2AuthenticationFailedException {

        // Find application
        final Optional<ApplicationEntity> application = repositoryCatalogue.getApplicationRepository().findById(applicationId);
        if (application.isEmpty()) {
            logger.warn("Application with given ID is not present: {}", applicationId);
            throw new Fido2AuthenticationFailedException("Application with given ID is not present: " + applicationId);
        }

        final Date currentTimestamp = new Date();

        // Obtain just the activation code part, just in case there was a value with signature
        final String[] split = challengeValue.split("#", 1);
        final String activationCode = split[0];

        // Only allow created activations to be finished
        ActivationRecordEntity activation = activationQueryService.findActivationByCodeWithoutLock(applicationId, activationCode, List.of(ActivationStatus.CREATED), currentTimestamp).orElseThrow(() -> {
            logger.warn("Activation with activation code: {} could not be obtained. It either does not exist or it already expired.", activationCode);
            // Rollback is not required, error occurs before writing to database
            return new Fido2AuthenticationFailedException("Activation failed");
        });

        final String activationId = activation.getActivationId();
        final String userId = activation.getUserId();

        final RegistrationChallenge assertionChallenge = new RegistrationChallenge();
        assertionChallenge.setChallenge(challengeValue);
        assertionChallenge.setApplicationId(applicationId);
        assertionChallenge.setActivationId(activationId);
        assertionChallenge.setUserId(userId);
        return assertionChallenge;
    }

    @Override
    @Transactional
    public void revokeRegistrationByChallengeValue(String applicationId, String challengeValue) throws Fido2AuthenticationFailedException {
        final Date currentTimestamp = new Date();

        // Find application
        final Optional<ApplicationEntity> application = repositoryCatalogue.getApplicationRepository().findById(applicationId);
        if (application.isEmpty()) {
            logger.warn("Application with given ID is not present: {}", applicationId);
            throw new Fido2AuthenticationFailedException("Application with given ID is not present: " + applicationId);
        }

        // Obtain just the activation code part, just in case there was a value with signature
        final String[] split = challengeValue.split("#", 1);
        final String activationCode = split[0];

        final List<ActivationStatus> statuses = List.of(ActivationStatus.CREATED, ActivationStatus.PENDING_COMMIT, ActivationStatus.ACTIVE, ActivationStatus.BLOCKED);
        final ActivationRecordEntity activation = activationQueryService.findActivationByCodeWithoutLock(applicationId, activationCode, statuses, currentTimestamp).orElseThrow(() -> {
            logger.warn("Activation with activation code: {} could not be obtained. It either does not exist or it already expired.", activationCode);
            // Rollback is not required, error occurs before writing to database
            return new Fido2AuthenticationFailedException("Activation could not be found");
        });

        final String activationId = activation.getActivationId();
        try {
            final RemoveActivationRequest removeActivationRequest = new RemoveActivationRequest();
            removeActivationRequest.setActivationId(activationId);
            removeActivationRequest.setRevokeRecoveryCodes(true);
            removeActivationRequest.setExternalUserId(null);
            activations.removeActivation(removeActivationRequest);
        } catch (GenericServiceException e) {
            throw new Fido2AuthenticationFailedException("Activation could not have been removed.", e);
        }

    }

    @Override
    @Transactional(readOnly = true)
    public boolean registrationAllowed(String applicationId, String credentialId, String attestationFormat, byte[] aaguid) throws Exception {
        final GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
        configRequest.setApplicationId(applicationId);
        final GetApplicationConfigResponse configResponse = applicationConfig.getApplicationConfig(configRequest);
        final String aaguidStr = bytesToUUID(aaguid).toString();
        Optional<ApplicationConfigurationItem> configFmt = configResponse.getApplicationConfigs().stream()
                .filter(cfg -> CONFIG_KEY_ALLOWED_ATTESTATION_FMT.equals(cfg.getKey()))
                .findFirst();

        if (configFmt.isPresent()) {
            final boolean attestationRejected = configFmt.get().getValues().stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .noneMatch(attestationFormat::equals);
            if (attestationRejected) {
                logger.warn("Rejected attestation format for FIDO2 registration: {}", attestationFormat);
                return false;
            }
        }

        Optional<ApplicationConfigurationItem> configAaguids = configResponse.getApplicationConfigs().stream()
                .filter(cfg -> CONFIG_KEY_ALLOWED_AAGUIDS.equals(cfg.getKey()))
                .findFirst();

        if (configAaguids.isPresent()) {
            final boolean aaguidRejected = configAaguids.get().getValues().stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .noneMatch(aaguidStr::equals);
            if (aaguidRejected) {
                logger.warn("Rejected AAGUID value for FIDO2 registration: {}", aaguidStr);
                return false;
            }
        }

        final List<ActivationRecordEntity> existingActivations = activationQueryService.findByExternalId(applicationId, credentialId);
        if (!existingActivations.isEmpty()) {
            logger.warn("Rejected duplicate external ID for registration, application ID: {}, external ID: {}", applicationId, credentialId);
            return false;
        }

        return true;
    }

    private UUID bytesToUUID(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        final ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        long mostSigBits = byteBuffer.getLong();
        long leastSigBits = byteBuffer.getLong();
        return new UUID(mostSigBits, leastSigBits);
    }
}
