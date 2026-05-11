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
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Date;
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
    private final AuditingServiceBehavior auditingServiceBehavior;

    /**
     * Sign data with ECDSA and ML-DSA signatures for given data using public key associated with given activation ID.
     *
     * @param request Request with ECDSA signature.
     * @return ECDSA signature for provided data payload.
     * @throws GenericServiceException In case signature verification fails.
     */
    @Transactional(readOnly = true)
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
            final byte[] signatureEcdsa;
            if (activation.getVersion() == 3) {
                // Legacy activations use ECDSA on P-256 curve
                signatureEcdsa = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).generateSignatureForActivation(KeyType.ECDSA_P256, dataRaw, activation);
            } else {
                signatureEcdsa = cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).generateSignatureForActivation(KeyType.ECDSA_P384, dataRaw, activation);
            }
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
            final String signatureFormatName = signatureFormat != null ? signatureFormat.name() : null;

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

            // Resolve the asymmetric key type to be used for verification (and audit log)
            final KeyType resolvedKeyType = resolveKeyType(signatureType, activation);

            final Date currentTimestamp = new Date();
            final byte[] dataBytes;
            final byte[] signatureBytes;
            final byte[] signatureBytesDER;
            try {
                dataBytes = Base64.getDecoder().decode(data);
                signatureBytes = Base64.getDecoder().decode(signature);
                signatureBytesDER = signatureDER(signatureFormat, signatureBytes);
            } catch (IllegalArgumentException | JOSEException ex) {
                logger.warn("Asymmetric signature payload could not be decoded, activation ID: {}", activationId, ex);
                auditingServiceBehavior.logAsymmetricSignatureAuditRecord(activation, data, signature, resolvedKeyType.name(), signatureFormatName,
                        false, "asymmetric_signature_format_invalid", currentTimestamp);
                return VerifyAsymmetricSignatureResponse.builder()
                        .signatureValid(false)
                        .build();
            }

            final boolean signatureValid = switch (signatureType) {
                case ECDSA -> {
                    if (activation.getVersion() == 3) {
                        // Legacy activations use ECDSA on P-256 curve
                        yield cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).verifySignatureForActivation(resolvedKeyType, dataBytes, signatureBytesDER, activation);
                    }
                    yield cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).verifySignatureForActivation(resolvedKeyType, dataBytes, signatureBytesDER, activation);
                }
                case MLDSA -> cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).verifySignatureForActivation(resolvedKeyType, dataBytes, signatureBytesDER, activation);
            };

            // Create the asymmetric signature audit log record (success or failure)
            final String note;
            if (signatureValid) {
                note = "asymmetric_signature_ok";
            } else {
                note = "asymmetric_signature_does_not_match";
            }
            auditingServiceBehavior.logAsymmetricSignatureAuditRecord(activation, data, signature, resolvedKeyType.name(), signatureFormatName,
                    signatureValid, note, currentTimestamp);

            return VerifyAsymmetricSignatureResponse.builder()
                    .signatureValid(signatureValid)
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
     * Resolve the asymmetric key type to be used for verification based on the requested signature type
     * and the activation's crypto algorithm/version. Returns {@code null} when the requested signature type
     * is not supported by the activation's crypto algorithm.
     *
     * @param signatureType Requested asymmetric signature type.
     * @param activation    Activation record.
     * @return Asymmetric key type to use for verification.
     * @throws GenericServiceException In case the key type is invalid.
     */
    private KeyType resolveKeyType(AsymmetricSignatureType signatureType, ActivationRecordEntity activation) throws GenericServiceException {
        return switch (signatureType) {
            case ECDSA -> {
                if (activation.getVersion() != null && activation.getVersion() == 3) {
                    yield KeyType.ECDSA_P256;
                }
                yield switch (activation.getCryptoAlgorithm()) {
                    case EC_P384, EC_P384_ML_L3, EC_P384_ML_L5 -> KeyType.ECDSA_P384;
                    default -> throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                };
            }
            case MLDSA -> switch (activation.getCryptoAlgorithm()) {
                case EC_P384_ML_L3 -> KeyType.MLDSA_65;
                case EC_P384_ML_L5 -> KeyType.MLDSA_87;
                default -> throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            };
        };
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
