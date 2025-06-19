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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.service.model.UniqueValueParam;
import com.wultra.security.powerauth.app.server.service.util.ReplayAttackUtils;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.RemoveTokenRequest;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.response.CreateTokenResponse;
import com.wultra.security.powerauth.client.model.response.RemoveTokenResponse;
import com.wultra.security.powerauth.client.model.response.ValidateTokenResponse;
import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import com.wultra.security.powerauth.app.server.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.app.server.database.model.ServerPrivateKey;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.TokenEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.database.repository.TokenRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.TokenInfo;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.replay.ReplayVerificationService;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import com.wultra.security.powerauth.crypto.server.token.ServerTokenGenerator;
import com.wultra.security.powerauth.crypto.server.token.ServerTokenVerifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

/**
 * Behavior that contains methods related to simple token-based authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TokenBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final ReplayVerificationService replayVerificationService;
    private final ActivationContextValidator activationValidator;
    private final TemporaryKeyBehavior temporaryKeyBehavior;
    private final TokenRepository tokenRepository;

    // Business logic implementation classes
    private final ServerTokenGenerator tokenGenerator = new ServerTokenGenerator();
    private final ServerTokenVerifier tokenVerifier = new ServerTokenVerifier();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    // Helper classes
    private final SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    private final ObjectMapper objectMapper;
    private final ApplicationVersionRepository applicationVersionRepository;

    /**
     * Method that creates a new token provided activation.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param request Request with the activation ID, signature type and ephemeral public key.
     * @return Response with a newly created token information (ECIES encrypted).
     * @throws GenericServiceException In case a business error occurs.
     */
    @Transactional
    public CreateTokenResponse createToken(CreateTokenRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String version = request.getProtocolVersion();
            final SignatureType signatureType = request.getSignatureType();
            final String temporaryKeyId = request.getTemporaryKeyId();

            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );
            final EncryptedResponse encryptedResponse = createToken(activationId, applicationKey, encryptedRequest, signatureType.name(), version, temporaryKeyId, keyConvertor);
            final CreateTokenResponse response = new CreateTokenResponse();
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());
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
     * Method that validates provided token-based authentication credentials.
     *
     * @param request Request with the token-based authentication credentials.
     * @return Response with the validation results.
     * @throws GenericServiceException In case of the business logic error.
     */
    @Transactional
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) throws GenericServiceException {
        try {
            // Verify the token timestamp validity
            final long currentTimeMillis = System.currentTimeMillis();
            final long requestTimestamp = request.getTimestamp();
            if (requestTimestamp < currentTimeMillis - powerAuthServiceConfiguration.getTokenTimestampValidity().toMillis()) {
                logger.warn("Invalid request - token timestamp is too old for token ID: {}, request timestamp: {}", request.getTokenId(), requestTimestamp);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.TOKEN_TIMESTAMP_TOO_OLD);
            }
            if (requestTimestamp > currentTimeMillis + powerAuthServiceConfiguration.getTokenTimestampForwardValidity().toMillis()) {
                logger.warn("Invalid request - token timestamp is set too much in the future for token ID: {}, request timestamp: {}", request.getTokenId(), requestTimestamp);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.TOKEN_TIMESTAMP_TOO_IN_FUTURE);
            }

            final String tokenId = request.getTokenId();
            final byte[] nonce = Base64.getDecoder().decode(request.getNonce());
            final byte[] timestamp = tokenVerifier.convertTokenTimestamp(request.getTimestamp());
            final byte[] tokenDigest = Base64.getDecoder().decode(request.getTokenDigest());

            // Lookup the token
            final Optional<TokenEntity> tokenEntityOptional = tokenRepository.findById(tokenId);
            if (tokenEntityOptional.isEmpty()) {
                // Instead of throwing INVALID_TOKEN exception a response with invalid token is returned
                final ValidateTokenResponse response = new ValidateTokenResponse();
                response.setTokenValid(false);
                return response;
            }
            final TokenEntity token = tokenEntityOptional.get();

            // Check if the activation is in correct state
            final ActivationRecordEntity activation = token.getActivation();
            final byte[] tokenSecret = Base64.getDecoder().decode(token.getTokenSecret());
            final boolean isTokenValid;
            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);
            if (!ActivationStatus.ACTIVE.equals(activation.getActivationStatus())) {
                logger.info("Activation is not ACTIVE, activation ID: {}", activation.getActivationId());
                isTokenValid = false;
            } else {
                // Check MAC token verification request for replay attacks and persist unique value from request
                final UniqueValueParam param = new UniqueValueParam();
                param.setUniqueValueType(UniqueValueType.MAC_TOKEN);
                param.setApplicationKey(null);
                param.setEphemeralPublicKey(null);
                param.setNonce(request.getNonce());
                param.setIdentifier(tokenId);
                replayVerificationService.checkAndPersistUniqueValue(request.getProtocolVersion(),
                        new Date(request.getTimestamp()),
                        param
                );
                // Validate MAC token
                isTokenValid = tokenVerifier.validateTokenDigest(nonce, timestamp, request.getProtocolVersion(), tokenSecret, tokenDigest);
            }

            final ValidateTokenResponse response = new ValidateTokenResponse();
            response.setTokenValid(isTokenValid);
            response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            response.setBlockedReason(activation.getBlockedReason());
            response.setActivationId(activation.getActivationId());
            response.setApplicationId(activation.getApplication().getId());
            response.getApplicationRoles().addAll(activation.getApplication().getRoles());
            response.getActivationFlags().addAll(activation.getFlags());
            response.setUserId(activation.getUserId());
            response.setSignatureType(signatureTypeConverter.convertFrom(token.getSignatureTypeCreated()));
            return response;
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
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Remove token with provided ID.
     *
     * @param request Request with token ID.
     * @return Token removal response.
     */
    @Transactional
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) throws GenericServiceException {
        try {
            final String tokenId = request.getTokenId();
            boolean removed = false;

            final Optional<TokenEntity> tokenEntityOptional = tokenRepository.findById(tokenId);

            // Token was found and activation ID corresponds to the correct user.
            if (tokenEntityOptional.isPresent()) {
                final TokenEntity token = tokenEntityOptional.get();
                if (token.getActivation().getActivationId().equals(request.getActivationId())) {
                    tokenRepository.delete(token);
                    removed = true;
                }
            }

            final RemoveTokenResponse response = new RemoveTokenResponse();
            response.setRemoved(removed);
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Create a new token implementation.
     *
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @param encryptedRequest Encrypted request.
     * @param signatureType Signature type.
     * @param protocolVersion Protocol version.
     * @param keyConversion Key conversion utility class.
     * @return Encrypted Response with a newly created token information.
     * @throws GenericServiceException In case a business error occurs.
     */
    private EncryptedResponse createToken(String activationId, String applicationKey, EncryptedRequest encryptedRequest,
                                          String signatureType, String protocolVersion, String temporaryKeyId, KeyConvertor keyConversion) throws GenericServiceException {
        try {
            // Lookup the activation
            final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            final UniqueValueParam uniqueValueParam = ReplayAttackUtils.deriveUniqueValuesActivationScope(protocolVersion, applicationKey, encryptedRequest.getEphemeralPublicKey(), encryptedRequest.getNonce(), temporaryKeyId, activationId);
            if (encryptedRequest.getTimestamp() != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        protocolVersion,
                        new Date(encryptedRequest.getTimestamp()),
                        uniqueValueParam
                );
            }

            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());
            final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);

            // KEY_SERVER_PRIVATE is used in Crypto version 3.0 for ECIES, note that in version 2.0 KEY_SERVER_MASTER_PRIVATE is used
            final PrivateKey serverPrivateKey = keyConversion.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get application secret and transport key used in sharedInfo2 parameter of ECIES
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConversion.convertSharedSecretKeyToBytes(transportKey);

            // Get temporary or server key, depending on availability
            final PrivateKey encryptorPrivateKey = (temporaryKeyId != null) ? temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, applicationKey, activationId) : serverPrivateKey;

            // Get server encryptor
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.CREATE_TOKEN,
                    new EncryptorParameters(protocolVersion, applicationKey, activationId, temporaryKeyId),
                    new ServerEncryptorSecrets(encryptorPrivateKey, applicationVersion.getApplicationSecret(), transportKeyBytes)
            );
            // Try to decrypt request data, the data must not be empty. Currently only '{}' is sent in request data. Ignore result of decryption.
            serverEncryptor.decryptRequest(encryptedRequest);

            // Generate unique token ID.
            String tokenId = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getGenerateTokenIdIterations(); i++) {
                String tmpTokenId = tokenGenerator.generateTokenId();
                final Optional<TokenEntity> tmpTokenOptional = tokenRepository.findById(tmpTokenId);
                if (tmpTokenOptional.isEmpty()) {
                    tokenId = tmpTokenId;
                    break;
                } // ... else this token ID has a collision, reset it and try to find another one
            }
            if (tokenId == null) {
                logger.error("Unable to generate token");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_TOKEN);
            }
            // Perform the following operations before writing to database to avoid rollbacks.
            final String tokenSecret = Base64.getEncoder().encodeToString(tokenGenerator.generateTokenSecret());
            final TokenInfo tokenInfo = new TokenInfo();
            tokenInfo.setTokenId(tokenId);
            tokenInfo.setTokenSecret(tokenSecret);

            final byte[] tokenBytes = objectMapper.writeValueAsBytes(tokenInfo);

            // Encrypt response bytes
            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(tokenBytes);

            // Create a new token
            final TokenEntity token = new TokenEntity();
            token.setTokenId(tokenId);
            token.setTokenSecret(tokenSecret);
            token.setActivation(activation);
            token.setTimestampCreated(Calendar.getInstance().getTime());
            token.setSignatureTypeCreated(signatureType);
            tokenRepository.save(token);

            return encryptedResponse;

        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EncryptorException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, serialization error can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }


}
