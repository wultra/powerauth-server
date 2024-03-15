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
import com.wultra.powerauth.fido2.rest.model.entity.RegistrationChallenge;
import com.wultra.powerauth.fido2.service.provider.RegistrationProvider;
import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.Protocols;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Optional;

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
    private final ServiceBehaviorCatalogue serviceBehaviorCatalogue;

    private final KeyConvertor keyConvertor = new KeyConvertor();

    @Autowired
    public PowerAuthRegistrationProvider(RepositoryCatalogue repositoryCatalogue, ServiceBehaviorCatalogue serviceBehaviorCatalogue) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.serviceBehaviorCatalogue = serviceBehaviorCatalogue;
    }

    @Override
    @Transactional
    public RegistrationChallenge provideChallengeForRegistration(String userId, String applicationId) throws GenericServiceException {
        final InitActivationResponse initActivationResponse = serviceBehaviorCatalogue.getActivationServiceBehavior()
                .initActivation(Protocols.FIDO2, applicationId, userId, null, null, ActivationOtpValidation.NONE, null, null, keyConvertor);
        final RegistrationChallenge registrationChallenge = new RegistrationChallenge();
        registrationChallenge.setUserId(initActivationResponse.getUserId());
        registrationChallenge.setApplicationId(initActivationResponse.getApplicationId());
        registrationChallenge.setActivationId(initActivationResponse.getActivationId());
        registrationChallenge.setChallenge(initActivationResponse.getActivationCode());
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
        final ActivationRecordEntity activationRecordEntity = repositoryCatalogue.getActivationRepository()
                .findCreatedActivationWithoutLock(applicationId, activationCode, List.of(ActivationStatus.CREATED), currentTimestamp);

        if (activationRecordEntity == null) {
            throw new Fido2AuthenticationFailedException("Activation failed");
        }

        final String activationId = activationRecordEntity.getActivationId();
        final String userId = activationRecordEntity.getUserId();

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
        final ActivationRecordEntity activationRecordEntity = repositoryCatalogue.getActivationRepository()
                .findCreatedActivationWithoutLock(applicationId, activationCode, statuses, currentTimestamp);

        if (activationRecordEntity == null) {
            // Registration was not completed.
            return;
        }

        final String activationId = activationRecordEntity.getActivationId();
        try {
            serviceBehaviorCatalogue.getActivationServiceBehavior().removeActivation(activationId, null, true);
        } catch (GenericServiceException e) {
            throw new Fido2AuthenticationFailedException("Activation could not have been removed.", e);
        }

    }

    @Override
    @Transactional(readOnly = true)
    public boolean registrationAllowed(String applicationId, String credentialId, String attestationFormat, byte[] aaguid) throws Exception {
        final ApplicationConfigServiceBehavior configService = serviceBehaviorCatalogue.getApplicationConfigServiceBehavior();
        final GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
        configRequest.setApplicationId(applicationId);
        final GetApplicationConfigResponse configResponse = configService.getApplicationConfig(configRequest);
        final String aaguidStr = new String(aaguid, StandardCharsets.UTF_8);
        Optional<ApplicationConfigurationItem> configFmt = configResponse.getApplicationConfigs().stream()
                .filter(cfg -> CONFIG_KEY_ALLOWED_ATTESTATION_FMT.equals(cfg.getKey()))
                .findFirst();

        if (configFmt.isPresent()) {
            List<String> allowedFmts = configFmt.get().getValues();
            if (!allowedFmts.contains(attestationFormat)) {
                logger.warn("Rejected attestation format for FIDO2 registration: {}", attestationFormat);
                return false;
            }
        }

        Optional<ApplicationConfigurationItem> configAaguids = configResponse.getApplicationConfigs().stream()
                .filter(cfg -> CONFIG_KEY_ALLOWED_AAGUIDS.equals(cfg.getKey()))
                .findFirst();

        if (configAaguids.isPresent()) {
            List<String> allowedAaguids = configAaguids.get().getValues();
            if (!allowedAaguids.contains(aaguidStr)) {
                logger.warn("Rejected AAGUID value for FIDO2 registration: {}", aaguidStr);
                return false;
            }
        }

        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final List<ActivationRecordEntity> existingActivations = activationRepository.findByExternalId(applicationId, credentialId);
        if (!existingActivations.isEmpty()) {
            logger.warn("Rejected duplicate external ID for registration, application ID: {}, external ID: {}", applicationId, credentialId);
            return false;
        }

        return true;
    }
}
