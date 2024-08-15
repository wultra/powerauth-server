/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wultra.security.powerauth.client.model.entity.TemporaryPublicKeyRequestClaims;
import com.wultra.security.powerauth.client.model.entity.TemporaryPublicKeyResponseClaims;
import com.wultra.security.powerauth.client.model.request.RemoveTemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.RemoveTemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.converter.TemporaryPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.TemporaryKeyEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.database.repository.TemporaryKeyRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * Behavior class implementing the temporary key request related processes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class TemporaryKeyBehavior {

    @Data
    private static class TemporaryKeyResult {
        private byte[] secretKeyBytes;
        private PrivateKey privateKey;
        private PublicKey publicKey;
    }

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private final LocalizationProvider localizationProvider;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final ActivationRepository activationRepository;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final TemporaryKeyRepository temporaryKeyRepository;
    private final TemporaryPrivateKeyConverter temporaryPrivateKeyConverter;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final PowerAuthServerKeyFactory keyFactory = new PowerAuthServerKeyFactory();

    @Autowired
    public TemporaryKeyBehavior(PowerAuthServiceConfiguration powerAuthServiceConfiguration, LocalizationProvider localizationProvider, ApplicationVersionRepository applicationVersionRepository, ActivationRepository activationRepository, MasterKeyPairRepository masterKeyPairRepository, TemporaryKeyRepository temporaryKeyRepository, TemporaryPrivateKeyConverter temporaryPrivateKeyConverter, ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.localizationProvider = localizationProvider;
        this.applicationVersionRepository = applicationVersionRepository;
        this.activationRepository = activationRepository;
        this.masterKeyPairRepository = masterKeyPairRepository;
        this.temporaryKeyRepository = temporaryKeyRepository;
        this.temporaryPrivateKeyConverter = temporaryPrivateKeyConverter;
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    @Transactional
    public TemporaryPublicKeyResponse requestTemporaryKey(TemporaryPublicKeyRequest request) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException, GenericCryptoException, InvalidKeyException {

        if (request == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Get claims from JWT
        final DecodedJWT decodedJWT = JWT.decode(request.getJwt());
        final TemporaryPublicKeyRequestClaims requestClaims = buildTemporaryKeyClaims(decodedJWT);

        // Validate claims
        final String error = validateDecodedClaims(requestClaims);
        if (error != null) {
            logger.warn("Error occurred while decoding JWT claims: {}", error);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Obtain verifier secret and check JWT signature
        final TemporaryKeyResult temporaryKeyResult = obtainTemporaryKeyResult(requestClaims);
        try {
            final Algorithm algorithm = Algorithm.HMAC256(temporaryKeyResult.getSecretKeyBytes());
            final JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(decodedJWT);
        } catch (JWTVerificationException ex){
            logger.debug("JWT token verification failed: {}", ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        final Date currentTimestamp = new Date();

        // Generate new key and store it
        final TemporaryPublicKeyResponseClaims responseClaims = generateAndStoreNewKey(requestClaims, currentTimestamp);

        // Built and return the response claims
        try {
            final HashMap<String, Object> additionalClaims = buildAdditionalClaims(responseClaims, currentTimestamp);
            final Algorithm algorithm = Algorithm.ECDSA256((ECPublicKey) temporaryKeyResult.publicKey, (ECPrivateKey) temporaryKeyResult.privateKey);
            final String jwtResponse = JWT.create()
                    .withSubject(responseClaims.getKeyId())
                    .withExpiresAt(responseClaims.getExpiration())
                    .withIssuedAt(currentTimestamp)
                    .withPayload(additionalClaims)
                    .sign(algorithm);

            final TemporaryPublicKeyResponse response = new TemporaryPublicKeyResponse();
            response.setJwt(jwtResponse);
            return response;
        } catch (JWTCreationException ex){
            logger.debug("JWT token signature failed: {}", ex.getMessage(), ex);
            throw new GenericServiceException("INVALID_TEMPORARY_KEY_RESPONSE", "Unable to produce a valid temporary key response");
        }
    }

    @Transactional
    public RemoveTemporaryPublicKeyResponse removeTemporaryKey(RemoveTemporaryPublicKeyRequest requestObject) {
        temporaryKeyRepository.deleteById(requestObject.getId());
        final RemoveTemporaryPublicKeyResponse response = new RemoveTemporaryPublicKeyResponse();
        response.setRemoved(true);
        response.setId(requestObject.getId());
        return response;
    }

    /**
     * Get the temporary private key, decrypt if required.
     * @param id Key ID.
     * @param appKey App key.
     * @param activationId Activation ID.
     * @return Temporary private key.
     * @throws GenericServiceException In case some parameters did not match.
     * @throws InvalidKeySpecException In case the private key could not be converted.
     * @throws CryptoProviderException In case the crypto provider is not configured properly.
     */
    public PrivateKey temporaryPrivateKey(String id, String appKey, String activationId) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException {
        final Date currentTimestamp = new Date();
        final Optional<TemporaryKeyEntity> temporaryKeyEntity = temporaryKeyRepository.findById(id);
        if (temporaryKeyEntity.isEmpty()) {
            logger.error("Missing temporary key pair with ID: {}", id);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_TEMPORARY_KEY);
        }
        final TemporaryKeyEntity temporaryKey = temporaryKeyEntity.get();
        if (temporaryKey.getTimestampExpires().before(currentTimestamp)) {
            logger.error("Requesting expired temporary key pair with ID: {}", id);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_TEMPORARY_KEY);
        }
        if (!Objects.equals(temporaryKey.getAppKey(), appKey) || !Objects.equals(temporaryKey.getActivationId(), activationId)) {
            logger.error("Temporary key does not match request parameters, app key expected: {}, received: {}, activation ID expected: {}, received: {}",
                    temporaryKey.getAppKey(), appKey,
                    temporaryKey.getActivationId(), activationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_TEMPORARY_KEY);
        }
        final String serverPrivateKeyFromEntity = temporaryKey.getPrivateKeyBase64();
        final EncryptionMode serverPrivateKeyEncryptionMode = temporaryKey.getPrivateKeyEncryption();
        final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
        final String serverPrivateKeyBase64 = temporaryPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, temporaryKey.getId(), temporaryKey.getAppKey(), temporaryKey.getActivationId());
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
        return keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(serverPrivateKeyBytes));
    }

    /**
     * Get the temporary private key, decrypt if required.
     * @param id Key ID.
     * @param appKey App key.
     * @return Temporary private key.
     * @throws GenericServiceException In case some parameters did not match.
     * @throws InvalidKeySpecException In case the private key could not be converted.
     * @throws CryptoProviderException In case the crypto provider is not configured properly.
     */
    public PrivateKey temporaryPrivateKey(String id, String appKey) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException {
        return temporaryPrivateKey(id, appKey, null);
    }


    // Tasks for scheduling

    @Transactional
    public void expireTemporaryKeys() {
        final Date currentTimestamp = new Date();
        final int expiredCount = temporaryKeyRepository.deleteExpiredKeys(currentTimestamp);
        logger.debug("Removed {} expired temporary keys", expiredCount);
    }

    // Private methods

    private TemporaryPublicKeyRequestClaims buildTemporaryKeyClaims(DecodedJWT source) {
        final TemporaryPublicKeyRequestClaims destination = new TemporaryPublicKeyRequestClaims();
        destination.setApplicationKey(source.getClaim("applicationKey").asString());
        destination.setActivationId(source.getClaim("activationId").asString());
        destination.setChallenge(source.getClaim("challenge").asString());
        return destination;
    }

    private String validateDecodedClaims(TemporaryPublicKeyRequestClaims requestClaims) {
        if (requestClaims.getApplicationKey() == null && requestClaims.getActivationId() == null) {
            return "Either app key or activation ID must be specified.";
        }
        return null;
    }

    private TemporaryKeyResult obtainTemporaryKeyResult(TemporaryPublicKeyRequestClaims requestClaims) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, GenericServiceException, InvalidKeyException {
        final String applicationKey = requestClaims.getApplicationKey();
        if (applicationKey != null) {
            final ApplicationVersionEntity applicationVersionEntity = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersionEntity == null || !applicationVersionEntity.getSupported()) {
                throw new IllegalArgumentException("App version with provided app key not found.");
            }
            final String applicationSecret = applicationVersionEntity.getApplicationSecret();
            if (requestClaims.getActivationId() == null) {

                final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationVersionEntity.getApplication().getId());

                final PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(masterKeyPairEntity.getMasterKeyPrivateBase64()));
                final PublicKey publicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(masterKeyPairEntity.getMasterKeyPublicBase64()));

                final byte[] secretKeyBytes = Base64.getDecoder().decode(applicationSecret);

                final TemporaryKeyResult result = new TemporaryKeyResult();
                result.setSecretKeyBytes(secretKeyBytes);
                result.setPrivateKey(privateKey);
                result.setPublicKey(publicKey);
                return result;
            } else {

                final String appId = applicationVersionEntity.getApplication().getId();

                final Optional<ActivationRecordEntity> activationWithoutLock = activationRepository.findActivationWithoutLock(requestClaims.getActivationId());
                if (activationWithoutLock.isEmpty()) {
                    throw new IllegalArgumentException("Activation ID not found.");
                }
                final ActivationRecordEntity activation = activationWithoutLock.get();
                if (activation.getActivationStatus() != ActivationStatus.ACTIVE || !appId.equals(activation.getApplication().getId())) {
                    throw new IllegalArgumentException("Activation ID not found.");
                }

                final EncryptionMode encryptionMode = activation.getServerPrivateKeyEncryption();
                final String serverPrivateKeyBase64 = activation.getServerPrivateKeyBase64();
                final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(encryptionMode, serverPrivateKeyBase64);
                String decryptedServerPrivateKey = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());
                final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(decryptedServerPrivateKey);
                final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(serverPrivateKeyBytes);

                final byte[] serverPublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
                final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(serverPublicKeyBytes);

                final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
                final PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
                final SecretKey transportKey = keyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);

                final byte[] applicationSecretKeyBytes = Base64.getDecoder().decode(applicationSecret);
                final SecretKey secretKey = keyGenerator.deriveSecretKeyHmac(transportKey, applicationSecretKeyBytes);
                final byte[] secretKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(secretKey);

                final TemporaryKeyResult result = new TemporaryKeyResult();
                result.setSecretKeyBytes(secretKeyBytes);
                result.setPrivateKey(serverPrivateKey);
                result.setPublicKey(serverPublicKey);
                return result;
            }
         } else {
            throw new IllegalArgumentException("App key must be specified.");
         }
    }

    private TemporaryPublicKeyResponseClaims generateAndStoreNewKey(TemporaryPublicKeyRequestClaims requestClaims, Date currentTimestamp) throws CryptoProviderException, GenericServiceException {

        // Generate a temporary key pair
        final KeyPair temporaryKeyPair = keyGenerator.generateKeyPair();

        // Prepare the parameters key pair
        final String keyId = UUID.randomUUID().toString();
        final String applicationKey = requestClaims.getApplicationKey();
        final String activationId = requestClaims.getActivationId();
        final String challenge = requestClaims.getChallenge();
        final byte[] privateKeyBytes = keyConvertor.convertPrivateKeyToBytes(temporaryKeyPair.getPrivate());
        final String temporaryPublicKeyBase64 = Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(temporaryKeyPair.getPublic()));
        final Date expirationDate = Date.from(currentTimestamp.toInstant().plusMillis(powerAuthServiceConfiguration.getTemporaryKeyValidityMilliseconds().toMillis()));

        // Prepare encrypted temporary private key, if encryption is enabled
        final ServerPrivateKey temporaryPrivateKey = temporaryPrivateKeyConverter.toDBValue(
                privateKeyBytes,
                keyId,
                applicationKey,
                activationId
        );

        // Prepare and store the entity
        final TemporaryKeyEntity temporaryKeyEntity = new TemporaryKeyEntity();
        temporaryKeyEntity.setId(keyId);
        temporaryKeyEntity.setAppKey(applicationKey);
        temporaryKeyEntity.setActivationId(activationId);
        temporaryKeyEntity.setPrivateKeyEncryption(temporaryPrivateKey.encryptionMode());
        temporaryKeyEntity.setPrivateKeyBase64(temporaryPrivateKey.serverPrivateKeyBase64());
        temporaryKeyEntity.setPublicKeyBase64(temporaryPublicKeyBase64);
        temporaryKeyEntity.setTimestampExpires(expirationDate);
        final TemporaryKeyEntity savedEntity = temporaryKeyRepository.save(temporaryKeyEntity);

        // Prepare and return the result
        final TemporaryPublicKeyResponseClaims result = new TemporaryPublicKeyResponseClaims();
        result.setApplicationKey(savedEntity.getAppKey());
        result.setActivationId(savedEntity.getActivationId());
        result.setKeyId(savedEntity.getId());
        result.setPublicKey(savedEntity.getPublicKeyBase64());
        result.setExpiration(savedEntity.getTimestampExpires());
        result.setChallenge(challenge);
        return result;
    }

    private HashMap<String, Object> buildAdditionalClaims(TemporaryPublicKeyResponseClaims source, Date currentTimestamp) {
        final HashMap<String, Object> claims = new HashMap<>();
        if (source.getApplicationKey() != null) {
            claims.put("applicationKey", source.getApplicationKey());
        }
        if (source.getActivationId() != null) {
            claims.put("activationId", source.getActivationId());
        }
        claims.put("challenge", source.getChallenge());
        if (source.getPublicKey() != null) {
            claims.put("publicKey", source.getPublicKey());
        }
        claims.put("iat_ms", currentTimestamp.getTime());
        claims.put("exp_ms", source.getExpiration().getTime());
        return claims;
    }

}
