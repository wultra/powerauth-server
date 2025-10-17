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

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.util.jwt.JWSActivationSigner;
import com.wultra.security.powerauth.app.server.service.util.jwt.JWSActivationVerifier;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureType;
import com.wultra.security.powerauth.client.model.enumeration.v4.JwtSignatureFormat;
import com.wultra.security.powerauth.client.model.request.v4.SignJwtRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyJwtSignatureRequest;
import com.wultra.security.powerauth.client.model.response.v4.SignJwtResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyJwtSignatureResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static com.wultra.security.powerauth.app.server.service.util.jwt.JWSActivationSigner.JWT_ALGORITHM_NAME_MLDSA_65;

/**
 * Behavior class implementing the asymmetric JWT signature related processes. The
 * class separates the logic from the main service class.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("jwtSignatureServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class JwtSignatureServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationContextValidator activationValidator;
    private final CryptographyServiceFactory cryptographyServiceFactory;

    /**
     * Sign a JWT.
     *
     * @param request Sign JWT request.
     * @return Sign JWT response.
     * @throws GenericServiceException In case of invalid request or signature calculation failure.
     */
    public SignJwtResponse signJwt(SignJwtRequest request) throws GenericServiceException {
        final String activationId = request.getActivationId();
        final String data = request.getData();

        final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
            logger.warn("Activation used when computing JWT signature does not exist, activation ID: {}", activationId);
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });
        activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

        final ActivationStatus activationStatus = activation.getActivationStatus();
        if (activationStatus != ActivationStatus.ACTIVE) {
            logger.warn("Activation used when computing JWT signature is in incorrect status, activation ID: {}, status: {}", activationId, activationStatus);
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }

        final byte[] dataBytes = Base64URL.from(data).decode();
        final AsymmetricSignatureType signatureType = request.getSignatureType();
        return switch (request.getSignatureFormat()) {
            case JWS_COMPACT -> signJwtInternal(dataBytes, signatureType, activation);
            case JWS_JSON -> signJwsInternal(dataBytes, signatureType, activation);
        };
    }

    public SignJwtResponse signJwtInternal(byte[] dataBytes, AsymmetricSignatureType signatureType, ActivationRecordEntity activation) throws GenericServiceException {
        final SharedSecretAlgorithm sharedSecretAlgorithm = activation.getCryptoAlgorithm();
        final SignJwtResponse signJwtResponse = new SignJwtResponse();
        signJwtResponse.setSignatureFormat(JwtSignatureFormat.JWS_COMPACT);
        final JWSSigner signer = new JWSActivationSigner(
                cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()),
                activation
        );
        final JWSHeader header = switch (sharedSecretAlgorithm) {
            case EC_P256 -> new JWSHeader(JWSAlgorithm.ES256);
            case EC_P384 -> new JWSHeader(JWSAlgorithm.ES384);
            case EC_P384_ML_L3 -> {
                if (signatureType == null) {
                    yield new JWSHeader(JWSAlgorithm.ES384);
                } else {
                    final JWSAlgorithm alg = switch (signatureType) {
                        case ECDSA -> JWSAlgorithm.ES384;
                        case MLDSA -> new JWSAlgorithm(JWT_ALGORITHM_NAME_MLDSA_65);
                    };
                    yield new JWSHeader(alg);
                }
            }
            default -> {
                logger.warn("Unsupported shared secret algorithm in JWT sign request: {}", sharedSecretAlgorithm);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
        };
        try {
            final Payload payload = new Payload(dataBytes);
            final JWSObject jwsObject = new JWSObject(header, payload);
            jwsObject.sign(signer);
            final String signedData = jwsObject.serialize();
            signJwtResponse.setSignedData(signedData);
            return signJwtResponse;
        } catch (Exception e) {
            logger.warn("Error occurred while signing JWT: {}", e.getMessage());
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    private SignJwtResponse signJwsInternal(byte[] dataBytes, AsymmetricSignatureType signatureType, ActivationRecordEntity activation) throws GenericServiceException {
        final SharedSecretAlgorithm sharedSecretAlgorithm = activation.getCryptoAlgorithm();
        final SignJwtResponse signJwtResponse = new SignJwtResponse();
        signJwtResponse.setSignatureFormat(JwtSignatureFormat.JWS_JSON);
        final JWSSigner signer = new JWSActivationSigner(
                cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()),
                activation
        );
        try {
            final Payload payload = new Payload(dataBytes);
            final JWSObjectJSON jwsObject = new JWSObjectJSON(payload);
            switch (sharedSecretAlgorithm) {
                case EC_P256 -> {
                    final JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
                    jwsObject.sign(header, signer);
                }
                case EC_P384 -> {
                    final JWSHeader header = new JWSHeader(JWSAlgorithm.ES384);
                    jwsObject.sign(header, signer);
                }
                case EC_P384_ML_L3 -> {
                    if (signatureType == null) {
                        final JWSHeader ecdsaHeader = new JWSHeader(JWSAlgorithm.ES384);
                        final JWSHeader mldsaHeader = new JWSHeader(new JWSAlgorithm(JWT_ALGORITHM_NAME_MLDSA_65));
                        jwsObject.sign(ecdsaHeader, signer);
                        jwsObject.sign(mldsaHeader, signer);
                    } else {
                        final JWSAlgorithm alg = switch (signatureType) {
                            case ECDSA -> JWSAlgorithm.ES384;
                            case MLDSA -> new JWSAlgorithm(JWT_ALGORITHM_NAME_MLDSA_65);
                        };
                        final JWSHeader header = new JWSHeader(alg);
                        jwsObject.sign(header, signer);
                    }
                }
                default -> {
                    logger.warn("Unsupported shared secret algorithm in JWS sign request: {}", sharedSecretAlgorithm);
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                }
            }
            final String jwsJson = jwsObject.serializeGeneral();
            signJwtResponse.setSignedData(jwsJson);
            return signJwtResponse;
        } catch (Exception e) {
            logger.warn("Error occurred while signing JWS: {}", e.getMessage(), e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    /**
     * Verify a JWT signature.
     *
     * @param request Verify JWT signature request.
     * @return Verify JWT signature response.
     * @throws GenericServiceException In case signature verification failure.
     */
    @Transactional
    public VerifyJwtSignatureResponse verifyJwtSignature(VerifyJwtSignatureRequest request) throws GenericServiceException {
        final String activationId = request.getActivationId();
        final String signedData = request.getSignedData();

        final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
            logger.warn("Activation used when verifying JWT signature does not exist, activation ID: {}", activationId);
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });
        activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

        try {
            if (request.getSignatureFormat() == JwtSignatureFormat.JWS_COMPACT) {
                final SignedJWT signedJWT = SignedJWT.parse(signedData);
                final JWSActivationVerifier verifier = new JWSActivationVerifier(
                        cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()),
                        activation
                );
                final boolean verified = signedJWT.verify(verifier);
                return VerifyJwtSignatureResponse.builder()
                        .signatureValid(verified)
                        .build();
            } else {
                final JWSObjectJSON jwsObject = JWSObjectJSON.parse(signedData);
                final JWSActivationVerifier verifier = new JWSActivationVerifier(
                        cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()),
                        activation
                );

                int verifiedCount = 0;
                for (JWSObjectJSON.Signature signature : jwsObject.getSignatures()) {
                    final JWSHeader header = signature.getHeader();
                    if (verifier.supportedJWSAlgorithms().contains(header.getAlgorithm())) {
                        if (signature.verify(verifier)) {
                            verifiedCount++;
                        }
                    }
                }
                return VerifyJwtSignatureResponse.builder()
                        .signatureValid(verifiedCount == jwsObject.getSignatures().size())
                        .build();
            }
        } catch (Exception e) {
            logger.warn("Error occurred while verifying JWT/JWS: {}", e.getMessage(), e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

}
