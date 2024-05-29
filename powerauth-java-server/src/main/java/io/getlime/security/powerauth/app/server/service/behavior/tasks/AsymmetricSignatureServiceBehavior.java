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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.client.model.request.VerifyECDSASignatureRequest;
import com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Behavior class implementing the asymmetric (ECDSA) signature validation related processes. The
 * class separates the logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class AsymmetricSignatureServiceBehavior {

    private final ActivationRepository activationRepository;
    private final LocalizationProvider localizationProvider;
    private final ActivationContextValidator activationValidator;

    private final SignatureUtils signatureUtils = new SignatureUtils();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    @Autowired
    public AsymmetricSignatureServiceBehavior(ActivationRepository activationRepository, LocalizationProvider localizationProvider, ActivationContextValidator activationValidator) {
        this.activationRepository = activationRepository;
        this.localizationProvider = localizationProvider;
        this.activationValidator = activationValidator;
    }

    /**
     * Validate ECDSA signature for given data using public key associated with given activation ID.
     *
     * @param request Request with ECDSA verification request.
     * @return True in case signature validates for given data with provided public key, false otherwise.
     * @throws GenericServiceException In case signature verification fails.
     */
    @Transactional
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String data = request.getData();
            final String signature  = request.getSignature();
            if (activationId == null || data == null || signature == null) {
                logger.warn("Invalid request parameters in method verifyECDSASignature");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId);
            if (activation == null) {
                logger.warn("Activation used when verifying ECDSA signature does not exist, activation ID: {}", activationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }
            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            final byte[] devicePublicKeyData = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyData);
            final boolean matches = signatureUtils.validateECDSASignature(Base64.getDecoder().decode(data), Base64.getDecoder().decode(signature), devicePublicKey);

            final VerifyECDSASignatureResponse response = new VerifyECDSASignatureResponse();
            response.setSignatureValid(matches);
            return response;
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
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

}
