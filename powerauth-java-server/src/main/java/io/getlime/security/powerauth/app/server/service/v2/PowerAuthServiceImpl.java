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
package io.getlime.security.powerauth.app.server.service.v2;

import com.wultra.security.powerauth.client.v2.*;
import io.getlime.security.powerauth.app.server.converter.v3.KeyValueMapConverter;
import io.getlime.security.powerauth.app.server.converter.v3.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.exceptions.RollbackingServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

/**
 * Default implementation of the PowerAuth Server service.
 * The implementation of this service is divided into "behaviors"
 * responsible for individual processes.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @see PowerAuthService
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component("powerAuthServiceImplV2")
public class PowerAuthServiceImpl implements PowerAuthService {

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(PowerAuthServiceImpl.class);

    private final ServiceBehaviorCatalogue behavior;
    private final LocalizationProvider localizationProvider;
    private final KeyValueMapConverter keyValueMapConverter;

    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Service constructor.
     * @param behavior Service behavior catalogue.
     * @param localizationProvider Localization provider.
     * @param keyValueMapConverter Key value map converter.
     */
    public PowerAuthServiceImpl(ServiceBehaviorCatalogue behavior, LocalizationProvider localizationProvider, KeyValueMapConverter keyValueMapConverter) {
        this.behavior = behavior;
        this.localizationProvider = localizationProvider;
        this.keyValueMapConverter = keyValueMapConverter;
    }


    @Override
    @Transactional
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws GenericServiceException {
        if (request.getActivationIdShort() == null || request.getActivationNonce() == null || request.getEncryptedDevicePublicKey() == null
            || request.getActivationName() == null || request.getEphemeralPublicKey() == null || request.getApplicationKey() == null || request.getApplicationSignature() == null) {
            logger.warn("Invalid request parameters in method prepareActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            // Get request parameters
            String activationIdShort = request.getActivationIdShort();
            String activationNonceBase64 = request.getActivationNonce();
            String cDevicePublicKeyBase64 = request.getEncryptedDevicePublicKey();
            String activationName = request.getActivationName();
            String ephemeralPublicKey = request.getEphemeralPublicKey();
            String applicationKey = request.getApplicationKey();
            String applicationSignature = request.getApplicationSignature();
            String extras = request.getExtras();
            logger.info("PrepareActivationRequest received, activation ID short: {}", activationIdShort);
            PrepareActivationResponse response = behavior.v2().getActivationServiceBehavior().prepareActivation(activationIdShort, activationNonceBase64, ephemeralPublicKey, cDevicePublicKeyBase64, activationName, extras, applicationKey, applicationSignature, keyConvertor);
            logger.info("PrepareActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = {RuntimeException.class, RollbackingServiceException.class})
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws GenericServiceException {
        if (request.getApplicationKey() == null || request.getUserId() == null || request.getActivationOtp() == null || request.getActivationNonce() == null || request.getEncryptedDevicePublicKey() == null
                || request.getActivationName() == null || request.getEphemeralPublicKey() == null || request.getApplicationSignature() == null) {
            logger.warn("Invalid request parameters in method createActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // The maxFailedCount and activationExpireTimestamp values can be null, in this case default values are used
        try {
            // Get request parameters
            String applicationKey = request.getApplicationKey();
            String userId = request.getUserId();
            Long maxFailedCount = request.getMaxFailureCount();
            Date activationExpireTimestamp = XMLGregorianCalendarConverter.convertTo(request.getTimestampActivationExpire());
            String identity = request.getIdentity();
            String activationOtp = request.getActivationOtp();
            String activationNonceBase64 = request.getActivationNonce();
            String cDevicePublicKeyBase64 = request.getEncryptedDevicePublicKey();
            String activationName = request.getActivationName();
            String ephemeralPublicKey = request.getEphemeralPublicKey();
            String applicationSignature = request.getApplicationSignature();
            String extras = request.getExtras();
            logger.info("CreateActivationRequest received, user ID: {}", userId);
            CreateActivationResponse response = behavior.v2().getActivationServiceBehavior().createActivation(
                    applicationKey,
                    userId,
                    maxFailedCount,
                    activationExpireTimestamp,
                    identity,
                    activationOtp,
                    activationNonceBase64,
                    ephemeralPublicKey,
                    cDevicePublicKeyBase64,
                    activationName,
                    extras,
                    applicationSignature,
                    keyConvertor
            );
            logger.info("CreateActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getSignature() == null
                || request.getSignatureType() == null || request.getData() == null) {
            logger.warn("Invalid request parameters in method vaultUnlock");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // Vault unlock reason can be null, in this case unspecified reason is used
        try {

            // Get request data
            String activationId = request.getActivationId();
            String applicationKey = request.getApplicationKey();
            String signature = request.getSignature();
            SignatureType signatureType = request.getSignatureType();
            String data = request.getData();
            String reason = request.getReason();

            logger.info("VaultUnlockRequest received, activation ID: {}", activationId);

            // Reject 1FA signatures.
            if (signatureType.equals(SignatureType.BIOMETRY)
                    || signatureType.equals(SignatureType.KNOWLEDGE)
                    || signatureType.equals(SignatureType.POSSESSION)) {
                logger.warn("Invalid signature type: {}", signatureType);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_SIGNATURE);
            }

            if (reason != null && reason.length() > 255) {
                logger.warn("Invalid vault unlock reason: {}", reason);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Save vault unlock reason into additional info which is logged in signature audit log.
            // If value unlock reason is missing, use default NOT_SPECIFIED value.
            KeyValueMap additionalInfo = new KeyValueMap();
            KeyValueMap.Entry entry = new KeyValueMap.Entry();
            entry.setKey(AdditionalInformation.VAULT_UNLOCKED_REASON);
            if (reason == null) {
                entry.setValue(AdditionalInformation.VAULT_UNLOCKED_REASON_NOT_SPECIFIED);
            } else {
                entry.setValue(reason);
            }
            additionalInfo.getEntry().add(entry);

            // Verify the signature
            boolean isSignatureValid = this.verifySignatureImplNonTransaction(activationId, applicationKey, data, signature, signatureType, additionalInfo);

            VaultUnlockResponse response = behavior.v2().getVaultUnlockServiceBehavior().unlockVault(activationId, isSignatureValid, keyConvertor);
            logger.info("VaultUnlockRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getSessionIndex() == null) {
            logger.warn("Invalid request parameters in method generateE2EPersonalizedEncryptionKey");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("GetPersonalizedEncryptionKeyRequest received, activation ID: {}", request.getActivationId());
            GetPersonalizedEncryptionKeyResponse response = behavior.v2().getEncryptionServiceBehavior().generateEncryptionKeyForActivation(
                    request.getActivationId(),
                    request.getSessionIndex(),
                    keyConvertor
            );
            logger.info("GetPersonalizedEncryptionKeyRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) throws GenericServiceException {
        if (request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getSessionIndex() == null) {
            logger.warn("Invalid request parameters in method generateE2ENonPersonalizedEncryptionKey");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("GetNonPersonalizedEncryptionKeyRequest received");
            GetNonPersonalizedEncryptionKeyResponse response = behavior.v2().getEncryptionServiceBehavior().generateNonPersonalizedEncryptionKeyForApplication(
                    request.getApplicationKey(),
                    request.getSessionIndex(),
                    request.getEphemeralPublicKey(),
                    keyConvertor
            );
            logger.info("GetNonPersonalizedEncryptionKeyRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public CreateTokenResponse createToken(CreateTokenRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getEphemeralPublicKey() == null) {
            logger.warn("Invalid request parameters in method createToken");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateTokenRequest received, activation ID: {}", request.getActivationId());
            CreateTokenResponse response = behavior.v2().getTokenBehavior().createToken(request, keyConvertor);
            logger.info("CreateTokenRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    private boolean verifySignatureImplNonTransaction(String activationId, String applicationKey, String dataString, String signature, SignatureType signatureType, KeyValueMap additionalInfo) throws GenericServiceException {
        com.wultra.security.powerauth.client.v3.SignatureType signatureTypeV3 = new io.getlime.security.powerauth.app.server.converter.v3.SignatureTypeConverter().convertFrom(signatureType);
        com.wultra.security.powerauth.client.v3.KeyValueMap additionalInfoV3 = keyValueMapConverter.fromKeyValueMap(additionalInfo);
        return behavior.getOnlineSignatureServiceBehavior().verifySignature(activationId, signatureTypeV3, signature, "2.1", additionalInfoV3, dataString, applicationKey, null, keyConvertor).isSignatureValid();
    }

}