/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.crypto.ProtocolVersionValidationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.enumeration.v3.ECDSASignatureFormat;
import com.wultra.security.powerauth.client.model.request.v3.SignECDSARequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifyECDSASignatureRequest;
import com.wultra.security.powerauth.client.model.response.v3.SignECDSAResponse;
import com.wultra.security.powerauth.client.model.response.v3.VerifyECDSASignatureResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Optional;

/**
 * Behavior class implementing the asymmetric (ECDSA) signature validation related processes. The
 * class separates the logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service("asymmetricSignatureServiceBehaviorV3")
@Slf4j
@AllArgsConstructor
public class AsymmetricSignatureServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationContextValidator activationValidator;
    private final CryptographyServiceFactory cryptographyServiceFactory;
    private final ProtocolVersionValidationService protocolVersionValidationService;

    /**
     * Sign data with ECDSA signature for given data using public key associated with given activation ID.
     *
     * @param request Request with ECDSA signature.
     * @return ECDSA signature for provided data payload.
     * @throws GenericServiceException In case signature verification fails.
     */
    @Transactional
    public SignECDSAResponse signDataWithECDSA(SignECDSARequest request) throws GenericServiceException {
        protocolVersionValidationService.checkProtocolVersionSupported(3);
        try {
            final String activationId = request.getActivationId();
            final String data = request.getData();

            final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
                logger.warn("Activation used when computing ECDSA signature does not exist, activation ID: {}", activationId);
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });
            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            final ActivationStatus activationStatus = activation.getActivationStatus();
            if (activationStatus != ActivationStatus.ACTIVE) {
                logger.warn("Activation used when computing ECDSA signature is in incorrect status, activation ID: {}, status: {}", activationId, activationStatus);
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            final byte[] dataRaw = Base64.getDecoder().decode(data);
            final byte[] signature = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).generateSignatureForActivation(KeyType.ECDSA_P256, dataRaw, activation);
            final String signatureBase64 = Base64.getEncoder().encodeToString(signature);

            final SignECDSAResponse response = new SignECDSAResponse();
            response.setSignature(signatureBase64);
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
     * Validate ECDSA signature for given data using public key associated with given activation ID.
     *
     * @param request Request with ECDSA verification request.
     * @return True in case signature validates for given data with provided public key, false otherwise.
     * @throws GenericServiceException In case signature verification fails.
     */
    @Transactional
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws GenericServiceException {
        protocolVersionValidationService.checkProtocolVersionSupported(3);
        try {
            final String activationId = request.getActivationId();
            final String data = request.getData();
            final String signature  = request.getSignature();
            final ECDSASignatureFormat signatureFormat = request.getSignatureFormat();

            final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);
            if (activationOptional.isEmpty()) {
                logger.warn("Activation used when verifying ECDSA signature does not exist, activation ID: {}", activationId);
                return VerifyECDSASignatureResponse.builder()
                        .signatureValid(false)
                        .build();
            }
            final ActivationRecordEntity activation = activationOptional.get();
            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            final byte[] dataBytes = Base64.getDecoder().decode(data);
            final byte[] signatureBytes = Base64.getDecoder().decode(signature);
            final byte[] signatureBytesDER = signatureDER(signatureFormat, signatureBytes);

            final boolean matches = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).verifySignatureForActivation(KeyType.ECDSA_P256, dataBytes, signatureBytesDER, activation);

            return VerifyECDSASignatureResponse.builder()
                    .signatureValid(matches)
                    .build();
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
     * Helper method to convert signature to DER format if needed.
     * @param signatureFormat Expected signature format.
     * @param signature Signature value in the provided format.
     * @return Signature value in DER format.
     * @throws JOSEException In case JOSE conversion fails.
     */
    private byte[] signatureDER(ECDSASignatureFormat signatureFormat, byte[] signature) throws JOSEException {
        return (signatureFormat == ECDSASignatureFormat.JOSE) ? ECDSA.transcodeSignatureToDER(signature) : signature;
    }

}
