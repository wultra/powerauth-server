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

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus;
import io.getlime.security.powerauth.app.server.database.model.entity.RecoveryCodeEntity;
import io.getlime.security.powerauth.app.server.database.repository.RecoveryCodeRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.v3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;
import java.util.List;

/**
 * Behavior class implementing processes related to recovery codes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoveryServiceBehavior {

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(RecoveryServiceBehavior.class);

    private final RecoveryCodeRepository recoveryCodeRepository;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();
    private final KeyGenerator keyGenerator = new KeyGenerator();

    @Autowired
    public RecoveryServiceBehavior(RecoveryCodeRepository recoveryCodeRepository, LocalizationProvider localizationProvider, PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.recoveryCodeRepository = recoveryCodeRepository;
        this.localizationProvider = localizationProvider;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
    }

    /**
     * Create recovery code for given user.
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws GenericServiceException In case of any error.
     */
    public CreateRecoveryCodeForUserResponse createRecoveryCodeForUser(CreateRecoveryCodeForUserRequest request) throws GenericServiceException {
        final Long applicationId = request.getApplicationId();
        final String userId = request.getUserId();
        final Long pukCount = request.getPukCount();

        // Check whether user has any recovery code in state CREATED or ACTIVE, in this case the recovery code needs to be revoked first
        List<RecoveryCodeEntity> existingRecoveryCodes = recoveryCodeRepository.findAllByApplicationIdAndUserId(applicationId, userId);
        for (RecoveryCodeEntity recoveryCodeEntity: existingRecoveryCodes) {
            if (recoveryCodeEntity.getStatus() == RecoveryCodeStatus.CREATED || recoveryCodeEntity.getStatus() == RecoveryCodeStatus.ACTIVE) {
                logger.warn("Create recovery code failed because of existing recovery codes, application ID: {}, user ID: {}", applicationId, userId);
                throw localizationProvider.buildExceptionForCode(ServiceError.RECOVERY_CODE_ALREADY_EXISTS);
            }
        }

        // TODO - Generate Recovery code and PUK codes based on secure postcard algorithm
        String recoveryCode = "";

        // Create and persist recovery code entity
        RecoveryCodeEntity recoveryCodeEntity = new RecoveryCodeEntity();
        recoveryCodeEntity.setUserId(userId);
        recoveryCodeEntity.setApplicationId(applicationId);
        recoveryCodeEntity.setFailedAttempts(0L);
        recoveryCodeEntity.setMaxFailedAttempts(powerAuthServiceConfiguration.getRecoveryMaxFailedAttempts());
        recoveryCodeEntity.setRecoveryCode(recoveryCode);
        recoveryCodeEntity.setStatus(RecoveryCodeStatus.CREATED);
        recoveryCodeEntity.setTimestampCreated(new Date());

        // TODO - attach PUK codes to recovery code entity

        // Generate nonce for secure postcard exchange
        byte[] randomBytes = keyGenerator.generateRandomBytes(16);
        String nonce = BaseEncoding.base64().encode(randomBytes);

        CreateRecoveryCodeForUserResponse response = new CreateRecoveryCodeForUserResponse();
        response.setNonce(nonce);
        response.setUserId(userId);
        response.setRecoveryCode(recoveryCode);
        response.setStatus(io.getlime.security.powerauth.v3.RecoveryCodeStatus.CREATED);
        // TODO - attach PUK codes to response

        return response;
    }

    /**
     * Create recovery code for given activation and set its status to ACTIVE.
     * @param request Create recovery code for activation request.
     * @return Create recovery code for activation response.
     * @throws GenericServiceException In case of any error.
     */
    public CreateRecoveryCodeForActivationResponse createRecoveryCodeForActivation(CreateRecoveryCodeForActivationRequest request) throws GenericServiceException {
        final Long applicationId = request.getApplicationId();
        final String activationId = request.getActivationId();

        // Check whether user has any recovery code in state CREATED or ACTIVE, in this case the recovery code needs to be revoked first
        List<RecoveryCodeEntity> existingRecoveryCodes = recoveryCodeRepository.findAllByApplicationIdAndActivationId(applicationId, activationId);
        for (RecoveryCodeEntity recoveryCodeEntity: existingRecoveryCodes) {
            if (recoveryCodeEntity.getStatus() == RecoveryCodeStatus.CREATED || recoveryCodeEntity.getStatus() == RecoveryCodeStatus.ACTIVE) {
                logger.warn("Create recovery code failed because of existing recovery codes, application ID: {}, activation ID: {}", applicationId, activationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.RECOVERY_CODE_ALREADY_EXISTS);
            }
        }

        // Generate random nonce
        byte[] randomBytes = keyGenerator.generateRandomBytes(16);
        String nonce = BaseEncoding.base64().encode(randomBytes);

        // TODO - Find user ID from activation
        String userId = "";

        // TODO - Generate Recovery code and PUK code
        String recoveryCode = "";

        // Create and persist recovery code entity
        RecoveryCodeEntity recoveryCodeEntity = new RecoveryCodeEntity();
        recoveryCodeEntity.setUserId(userId);
        recoveryCodeEntity.setApplicationId(applicationId);
        recoveryCodeEntity.setFailedAttempts(0L);
        recoveryCodeEntity.setMaxFailedAttempts(powerAuthServiceConfiguration.getRecoveryMaxFailedAttempts());
        recoveryCodeEntity.setRecoveryCode(recoveryCode);
        recoveryCodeEntity.setStatus(RecoveryCodeStatus.CREATED);
        recoveryCodeEntity.setTimestampCreated(new Date());

        // TODO - attach PUK codes to recovery code entity

        CreateRecoveryCodeForActivationResponse response = new CreateRecoveryCodeForActivationResponse();
        response.setActivationId(activationId);
        response.setRecoveryCode(recoveryCode);
        response.setStatus(io.getlime.security.powerauth.v3.RecoveryCodeStatus.CREATED);
        // TODO - attach PUK codes to response

        return response;
    }

    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws GenericServiceException {
        ConfirmRecoveryCodeResponse response = new ConfirmRecoveryCodeResponse();
        return response;
    }

    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws GenericServiceException {
        LookupRecoveryCodesResponse response = new LookupRecoveryCodesResponse();
        return response;
    }

    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws GenericServiceException {
        RevokeRecoveryCodesResponse response = new RevokeRecoveryCodesResponse();
        return response;
    }

    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws GenericServiceException {
        RecoveryCodeActivationResponse response = new RecoveryCodeActivationResponse();
        return response;
    }

}
