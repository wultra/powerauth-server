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

import io.getlime.security.powerauth.app.server.converter.v3.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.v2.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

/**
 * Default implementation of the PowerAuth Server service.
 * The implementation of this service is divided into "behaviors"
 * responsible for individual processes.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @see PowerAuthService
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component("PowerAuthServiceImplV2")
public class PowerAuthServiceImpl implements PowerAuthService {

    private ServiceBehaviorCatalogue behavior;

    private LocalizationProvider localizationProvider;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(PowerAuthServiceImpl.class);

    @Autowired
    public void setBehavior(ServiceBehaviorCatalogue behavior) {
        this.behavior = behavior;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    private final CryptoProviderUtil keyConversionUtilities = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    @Override
    @Transactional
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception {
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
            logger.info("PrepareActivationRequest received, activationIdShort: {}", activationIdShort);
            PrepareActivationResponse response = behavior.v2().getActivationServiceBehavior().prepareActivation(activationIdShort, activationNonceBase64, ephemeralPublicKey, cDevicePublicKeyBase64, activationName, extras, applicationKey, applicationSignature, keyConversionUtilities);
            logger.info("PrepareActivationRequest succeeded");
            return response;
        } catch (IllegalArgumentException ex) {
            logger.error("Unknown error occurred", ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        } catch (GenericServiceException ex) {
            logger.error("Unknown error occurred", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws Exception {
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
            logger.info("CreateActivationRequest received, userId: {}", userId);
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
                    keyConversionUtilities
            );
            logger.info("CreateActivationRequest succeeded");
            return response;
        } catch (IllegalArgumentException ex) {
            logger.error("Unknown error occurred", ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        } catch (GenericServiceException ex) {
            logger.error("Unknown error occurred", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception {
        try {

            // Get request data
            String activationId = request.getActivationId();
            String applicationKey = request.getApplicationKey();
            String signature = request.getSignature();
            SignatureType signatureType = request.getSignatureType();
            String data = request.getData();
            String reason = request.getReason();

            logger.info("VaultUnlockRequest received, activationId: {}", activationId);

            // Reject 1FA signatures.
            if (signatureType.equals(SignatureType.BIOMETRY)
                    || signatureType.equals(SignatureType.KNOWLEDGE)
                    || signatureType.equals(SignatureType.POSSESSION)) {
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_SIGNATURE);
            }

            if (reason != null && reason.length() > 255) {
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

            VaultUnlockResponse response = behavior.v2().getVaultUnlockServiceBehavior().unlockVault(activationId, isSignatureValid, keyConversionUtilities);
            logger.info("VaultUnlockRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            logger.error("Unknown error occurred", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest request) throws Exception {
        logger.info("GetPersonalizedEncryptionKeyRequest received, activationId: {}", request.getActivationId());
        GetPersonalizedEncryptionKeyResponse response = behavior.v2().getEncryptionServiceBehavior().generateEncryptionKeyForActivation(
                request.getActivationId(),
                request.getSessionIndex(),
                keyConversionUtilities
        );
        logger.info("GetPersonalizedEncryptionKeyRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) throws Exception {
        logger.info("GetNonPersonalizedEncryptionKeyRequest received");
        GetNonPersonalizedEncryptionKeyResponse response = behavior.v2().getEncryptionServiceBehavior().generateNonPersonalizedEncryptionKeyForApplication(
                request.getApplicationKey(),
                request.getSessionIndex(),
                request.getEphemeralPublicKey(),
                keyConversionUtilities
        );
        logger.info("GetNonPersonalizedEncryptionKeyRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public CreateTokenResponse createToken(CreateTokenRequest request) throws Exception {
        logger.info("CreateTokenRequest received, activationId: {}", request.getActivationId());
        CreateTokenResponse response = behavior.v2().getTokenBehavior().createToken(request, keyConversionUtilities);
        logger.info("CreateTokenRequest succeeded");
        return response;
    }

    private boolean verifySignatureImplNonTransaction(String activationId, String applicationKey, String dataString, String signature, SignatureType signatureType, KeyValueMap additionalInfo) throws Exception {
        io.getlime.security.powerauth.v3.SignatureType signatureTypeV3 = new io.getlime.security.powerauth.app.server.converter.v3.SignatureTypeConverter().convertFrom(signatureType);
        io.getlime.security.powerauth.v3.KeyValueMap additionalInfoV3 = new io.getlime.security.powerauth.app.server.converter.v3.KeyValueMapConverter().fromKeyValueMap(additionalInfo);
        return behavior.getSignatureServiceBehavior().verifySignature(activationId, signatureTypeV3, signature, additionalInfoV3, dataString, applicationKey, null, keyConversionUtilities).isSignatureValid();
    }

}