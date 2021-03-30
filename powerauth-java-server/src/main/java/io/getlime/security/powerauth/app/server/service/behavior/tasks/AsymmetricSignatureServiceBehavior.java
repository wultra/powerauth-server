/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Behavior class implementing the asymmetric (ECDSA) signature validation related processes. The
 * class separates the logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class AsymmetricSignatureServiceBehavior {

    private final ActivationRepository activationRepository;
    private final LocalizationProvider localizationProvider;

    private final SignatureUtils signatureUtils = new SignatureUtils();

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(AsymmetricSignatureServiceBehavior.class);

    @Autowired
    public AsymmetricSignatureServiceBehavior(ActivationRepository activationRepository, LocalizationProvider localizationProvider) {
        this.activationRepository = activationRepository;
        this.localizationProvider = localizationProvider;
    }

    /**
     * Validate ECDSA signature for given data using public key associated with given activation ID.
     * @param activationId Activation ID to be used for device public key lookup.
     * @param data Data that were signed, in Base64 format.
     * @param signature Provided signature to be verified, in Base64 format.
     * @param keyConversionUtilities Key converter provided by the client code.
     * @return True in case signature validates for given data with provided public key, false otherwise.
     * @throws GenericServiceException In case signature verification fails.
     */
    public boolean verifyECDSASignature(String activationId, String data, String signature, KeyConvertor keyConversionUtilities) throws GenericServiceException {
        try {
            final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId);
            if (activation == null) {
                logger.warn("Activation used when verifying ECDSA signature does not exist, activation ID: {}", activationId);
                return false;
            }
            final byte[] devicePublicKeyData = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyData);
            return signatureUtils.validateECDSASignature(BaseEncoding.base64().decode(data), BaseEncoding.base64().decode(signature), devicePublicKey);
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }

    }

}
