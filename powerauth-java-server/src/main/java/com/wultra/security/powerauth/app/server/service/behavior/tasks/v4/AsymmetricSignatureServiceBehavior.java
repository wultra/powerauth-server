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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureFormat;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureType;
import com.wultra.security.powerauth.client.model.request.v4.SignAsymmetricRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAsymmetricSignatureRequest;
import com.wultra.security.powerauth.client.model.response.v4.SignAsymmetricResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAsymmetricSignatureResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Optional;

/**
 * Behavior class implementing the asymmetric (ECDSA and ML-DSA) signature validation related processes. The
 * class separates the logic from the main service class.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("asymmetricSignatureServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class AsymmetricSignatureServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationContextValidator activationValidator;
    private final CryptographyServiceFactory cryptographyServiceFactory;

    /**
     * Sign data with ECDSA and ML-DSA signatures for given data using public key associated with given activation ID.
     *
     * @param request Request with ECDSA signature.
     * @return ECDSA signature for provided data payload.
     * @throws GenericServiceException In case signature verification fails.
     */
    @Transactional
    public SignAsymmetricResponse signData(SignAsymmetricRequest request) throws GenericServiceException {
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
            final byte[] signatureEcdsa = cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).generateSignatureForActivation(KeyType.ECDSA_P384, dataRaw, activation);
            final String signatureEcdsaBase64 = Base64.getEncoder().encodeToString(signatureEcdsa);
            final String signatureMldsaBase64 = switch (activation.getCryptoAlgorithm()) {
                case EC_P384_ML_L3 -> {
                    final byte[] signatureMldsa65 = cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).generateSignatureForActivation(KeyType.MLDSA_65, dataRaw, activation);
                    yield Base64.getEncoder().encodeToString(signatureMldsa65);
                }
                case EC_P384_ML_L5 -> {
                    final byte[] signatureMldsa87 = cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).generateSignatureForActivation(KeyType.MLDSA_87, dataRaw, activation);
                    yield Base64.getEncoder().encodeToString(signatureMldsa87);
                }
                default -> null;
            };

            final SignAsymmetricResponse response = new SignAsymmetricResponse();
            response.setSignatureEcdsa(signatureEcdsaBase64);
            response.setSignatureMldsa(signatureMldsaBase64);
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
     * Validate ECDSA or ML-DSA signature for given data using public key associated with given activation ID.
     *
     * @param request Request with ECDSA verification request.
     * @return Result of signature verification.
     * @throws GenericServiceException In case signature verification fails.
     */
    @Transactional
    public VerifyAsymmetricSignatureResponse verifySignature(VerifyAsymmetricSignatureRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String data = request.getData();
            final String signature  = request.getSignature();
            final AsymmetricSignatureType signatureType = request.getSignatureType();
            final AsymmetricSignatureFormat signatureFormat = request.getSignatureFormat();

            if (signatureType == AsymmetricSignatureType.MLDSA && signatureFormat == AsymmetricSignatureFormat.JOSE) {
                logger.warn("JOSE standard does not support ML-DSA yet, activation ID: {}", activationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);
            if (activationOptional.isEmpty()) {
                logger.warn("Activation used when verifying asymmetric signature does not exist, activation ID: {}", activationId);
                return VerifyAsymmetricSignatureResponse.builder()
                        .signatureValid(false)
                        .build();
            }
            final ActivationRecordEntity activation = activationOptional.get();
            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            final byte[] dataBytes = Base64.getDecoder().decode(data);
            final byte[] signatureBytes = Base64.getDecoder().decode(signature);
            final byte[] signatureBytesDER = signatureDER(signatureFormat, signatureBytes);

            final boolean matches = switch (signatureType) {
                case ECDSA -> cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).verifySignatureForActivation(KeyType.ECDSA_P384, dataBytes, signatureBytesDER, activation);
                case MLDSA -> switch (activation.getCryptoAlgorithm()) {
                    case EC_P384_ML_L3 -> cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).verifySignatureForActivation(KeyType.MLDSA_65, dataBytes, signatureBytesDER, activation);
                    case EC_P384_ML_L5 -> cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).verifySignatureForActivation(KeyType.MLDSA_87, dataBytes, signatureBytesDER, activation);
                    default -> false;
                };
            };

            return VerifyAsymmetricSignatureResponse.builder()
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
    private byte[] signatureDER(AsymmetricSignatureFormat signatureFormat, byte[] signature) throws JOSEException {
        return (signatureFormat == AsymmetricSignatureFormat.JOSE) ? ECDSA.transcodeSignatureToDER(signature) : signature;
    }

}
