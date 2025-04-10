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

package com.wultra.security.powerauth.app.server.service.crypto.v4;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.*;
import com.wultra.security.powerauth.app.server.database.model.*;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.TemporaryKeyEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.database.repository.TemporaryKeyRepository;
import com.wultra.security.powerauth.app.server.service.crypto.TemporaryKeyService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.crypto.TemporaryKeyResult;
import com.wultra.security.powerauth.app.server.service.util.jwt.MACVerifier16B;
import com.wultra.security.powerauth.client.model.entity.v4.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.SharedSecretResponse;
import com.wultra.security.powerauth.client.model.entity.v4.TemporaryPublicKeyRequestClaims;
import com.wultra.security.powerauth.client.model.entity.v4.TemporaryPublicKeyResponseClaims;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.*;

/**
 * Service for handling temporary keys with AEAD encryption on curve P-384 with optional PQC KEM.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class TemporaryKeyServiceAead extends TemporaryKeyService {

    private final ActivationRepository activationRepository;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final TemporaryPrivateKeyConverter temporaryPrivateKeyConverter;
    private final SharedSecretConverter sharedSecretConverter;
    private final TemporaryKeyRepository temporaryKeyRepository;
    private final LocalizationProvider localizationProvider;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final MasterPrivateKeysConverter masterPrivateKeysConverter;
    private final ServerPrivateKeysConverter serverPrivateKeysConverter;
    private final PublicKeysConverter publicKeysConverter;
    private final ObjectMapper objectMapper;

    private final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private final PowerAuthServerKeyFactory SERVER_KEY_FACTORY = new PowerAuthServerKeyFactory();
    private final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

    @Autowired
    public TemporaryKeyServiceAead(ActivationRepository activationRepository, PowerAuthServiceConfiguration powerAuthServiceConfiguration, TemporaryPrivateKeyConverter temporaryPrivateKeyConverter, SharedSecretConverter sharedSecretConverter, TemporaryKeyRepository temporaryKeyRepository, LocalizationProvider localizationProvider, ApplicationVersionRepository applicationVersionRepository, MasterKeyPairRepository masterKeyPairRepository, MasterPrivateKeysConverter masterPrivateKeysConverter, ObjectMapper objectMapper, ServerPrivateKeysConverter serverPrivateKeysConverter, PublicKeysConverter publicKeysConverter) {
        super(localizationProvider, temporaryKeyRepository);
        this.activationRepository = activationRepository;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.temporaryPrivateKeyConverter = temporaryPrivateKeyConverter;
        this.sharedSecretConverter = sharedSecretConverter;
        this.temporaryKeyRepository = temporaryKeyRepository;
        this.localizationProvider = localizationProvider;
        this.applicationVersionRepository = applicationVersionRepository;
        this.masterKeyPairRepository = masterKeyPairRepository;
        this.masterPrivateKeysConverter = masterPrivateKeysConverter;
        this.objectMapper = objectMapper;
        this.serverPrivateKeysConverter = serverPrivateKeysConverter;
        this.publicKeysConverter = publicKeysConverter;
    }

    /**
     * Request a temporary key.
     * @param jwt Temporary key request in JWT format.
     * @return Temporary key in JWT format.
     * @throws GenericServiceException In case of a cryptography error.
     */
    @Override
    public String requestTemporaryKey(String jwt) throws GenericServiceException {
        try {
            final SignedJWT decodedJWT = SignedJWT.parse(jwt);
            final TemporaryPublicKeyRequestClaims requestClaims = buildTemporaryKeyClaims(decodedJWT);

            // Validate claims
            final String error = validateDecodedClaims(requestClaims);
            if (error != null) {
                logger.warn("Error occurred while decoding JWT claims: {}", error);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Obtain verifier secret and check JWT signature
            final TemporaryKeyResult temporaryKeyResult = obtainTemporaryKeyResult(requestClaims);
            // TODO - switch to standard ECDSA verifier after key derived with KMAC-256 is used
            final MACVerifier16B verifier = new MACVerifier16B(temporaryKeyResult.getSecretKeyBytes());
            boolean verified = decodedJWT.verify(verifier);
            if (!verified) {
                logger.debug("JWT token verification failed.");
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final Date currentTimestamp = new Date();

            // Derive shared secret using SharedSecret algorithm
            final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(requestClaims.getSharedSecretRequest().getAlgorithm());
            final ResponseCryptogram sharedSecretResponse = deriveSharedSecret(temporaryKeyResult.getSharedSecretRequest(), algorithm);

            // Generate new key and store it
            final TemporaryPublicKeyResponseClaims responseClaims = storeTemporaryKey(requestClaims, currentTimestamp, sharedSecretResponse, algorithm);

            // Built and return the response claims
            // TODO - add Dilithium signature using custom signer
            final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES384).type(JOSEObjectType.JWT).build();
            final JWTClaimsSet claimsSet = buildClaims(responseClaims, currentTimestamp);

            final ECDSASigner signer = new ECDSASigner(temporaryKeyResult.getPrivateKey(), Curve.P_384);

            final SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            logger.error("Temporary key request is invalid", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            logger.error("Invalid key", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Temporary key request failed", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public PrivateKey extractTemporaryPrivateKey(String id, String appKey, String activationId) throws GenericServiceException {
        try {
            final TemporaryKeyEntity temporaryKey = fetchTemporaryKey(id, appKey, activationId);
            final String serverPrivateKeyFromEntity = temporaryKey.getPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = temporaryKey.getPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = temporaryPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, temporaryKey.getId(), temporaryKey.getAppKey(), temporaryKey.getActivationId());
            final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
            return KEY_CONVERTOR.convertBytesToPrivateKey(EcCurve.P384, serverPrivateKeyBytes);
        } catch (InvalidKeySpecException e) {
            logger.error("Invalid key", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException e) {
            logger.error("Temporary key request failed", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public SecretKey extractTemporarySharedSecret(String id, String appKey, String activationId) throws GenericServiceException {
        try {
            final TemporaryKeyEntity temporaryKey = fetchTemporaryKey(id, appKey, activationId);
            final String secretKeyBase64 = temporaryKey.getSecretKeyBase64();
            final EncryptionMode secretKeyEncryption = temporaryKey.getSecretKeyEncryption();
            final SharedSecret sharedSecretEncrypted = new SharedSecret(secretKeyEncryption, secretKeyBase64);
            final String sharedSecretBase64 = sharedSecretConverter.fromDBValue(sharedSecretEncrypted, temporaryKey.getId(), temporaryKey.getAppKey(), temporaryKey.getActivationId());
            final byte[] sharedSecretBytes = Base64.getDecoder().decode(sharedSecretBase64);
            return KEY_CONVERTOR.convertBytesToSharedSecretKey(sharedSecretBytes);
        } catch (InvalidKeySpecException e) {
            logger.error("Invalid key", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException e) {
            logger.error("Temporary key request failed", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    private TemporaryPublicKeyRequestClaims buildTemporaryKeyClaims(SignedJWT source) throws ParseException, GenericServiceException {
        final JWTClaimsSet jwtClaimsSet = source.getJWTClaimsSet();
        final TemporaryPublicKeyRequestClaims destination = new TemporaryPublicKeyRequestClaims();
        final String applicationKey = jwtClaimsSet.getStringClaim("applicationKey");
        final String activationId = jwtClaimsSet.getStringClaim("activationId");
        final String challenge = jwtClaimsSet.getStringClaim("challenge");
        final Object sharedSecretRequestClaim = jwtClaimsSet.getClaim("sharedSecretRequest");
        if (applicationKey == null || challenge == null || sharedSecretRequestClaim == null) {
            logger.error("Temporary key request is invalid");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        destination.setApplicationKey(applicationKey);
        destination.setActivationId(activationId);
        destination.setChallenge(challenge);
        final SharedSecretRequest sharedSecretRequest = objectMapper.convertValue(sharedSecretRequestClaim, SharedSecretRequest.class);
        destination.setSharedSecretRequest(sharedSecretRequest);
        return destination;
    }

    private String validateDecodedClaims(TemporaryPublicKeyRequestClaims requestClaims) {
        if (requestClaims.getApplicationKey() == null && requestClaims.getActivationId() == null) {
            return "Either app key or activation ID must be specified.";
        }
        if (requestClaims.getChallenge() == null) {
            return "Challenge must be specified.";
        }
        if (requestClaims.getSharedSecretRequest() == null) {
            return "Shared secret request must be specified.";
        }
        if (requestClaims.getSharedSecretRequest().getAlgorithm() == null) {
            return "Shared secret algorithm must be specified.";
        }
        if (!SharedSecretAlgorithm.EC_P384.toString().equals(requestClaims.getSharedSecretRequest().getAlgorithm())
                && !SharedSecretAlgorithm.EC_P384_ML_L3.toString().equals(requestClaims.getSharedSecretRequest().getAlgorithm())) {
            return "Invalid shared secret algorithm value.";
        }
        if (SharedSecretAlgorithm.EC_P384.toString().equals(requestClaims.getSharedSecretRequest().getAlgorithm())) {
            if (requestClaims.getSharedSecretRequest().getEcdhe() == null) {
                return "Shared secret ecdhe value must be specified for algorithm EC_P384.";
            }
        }
        if (SharedSecretAlgorithm.EC_P384_ML_L3.toString().equals(requestClaims.getSharedSecretRequest().getAlgorithm())) {
            if (requestClaims.getSharedSecretRequest().getEcdhe() == null) {
                return "Shared secret ecdhe value must be specified for algorithm EC_P384_ML_L3.";
            }
            if (requestClaims.getSharedSecretRequest().getMlkem() == null) {
                return "Shared secret mlkem value must be specified for algorithm EC_P384_ML_L3.";
            }
        }
        return null;
    }

    private JWTClaimsSet buildClaims(TemporaryPublicKeyResponseClaims source, Date currentTimestamp) {
        return new JWTClaimsSet.Builder()
                .subject(source.getKeyId())
                .expirationTime(source.getExpiration())
                .issueTime(currentTimestamp)
                .claim("applicationKey", source.getApplicationKey())
                .claim("activationId", source.getActivationId())
                .claim("challenge", source.getChallenge())
                .claim("sharedSecretResponse", source.getSharedSecretResponse())
                .claim("iat_ms", currentTimestamp.getTime())
                .claim("exp_ms", source.getExpiration().getTime())
                .build();
    }

    private TemporaryPublicKeyResponseClaims storeTemporaryKey(TemporaryPublicKeyRequestClaims requestClaims, Date currentTimestamp, ResponseCryptogram responseCryptogram, SharedSecretAlgorithm algorithm) throws CryptoProviderException, GenericServiceException {
        // Prepare the parameters key pair
        final String keyId = UUID.randomUUID().toString();
        final String applicationKey = requestClaims.getApplicationKey();
        final String activationId = requestClaims.getActivationId();
        final String challenge = requestClaims.getChallenge();
        final Date expirationDate = Date.from(currentTimestamp.toInstant().plusMillis(powerAuthServiceConfiguration.getTemporaryKeyValidity().toMillis()));

        // Prepare encrypted shard secret, if encryption is enabled
        final SharedSecret sharedSecretConverted = sharedSecretConverter.toDBValue(
                responseCryptogram.getSecretKey().getEncoded(), keyId, applicationKey, activationId);

        // Prepare and store the entity
        final TemporaryKeyEntity temporaryKeyEntity = new TemporaryKeyEntity();
        temporaryKeyEntity.setId(keyId);
        temporaryKeyEntity.setAppKey(applicationKey);
        temporaryKeyEntity.setActivationId(activationId);
        // Temporary keypair is no longer stored for V4
        temporaryKeyEntity.setPrivateKeyEncryption(EncryptionMode.NO_ENCRYPTION);
        temporaryKeyEntity.setPrivateKeyBase64(null);
        temporaryKeyEntity.setPublicKeyBase64(null);
        temporaryKeyEntity.setSecretKeyEncryption(sharedSecretConverted.encryptionMode());
        temporaryKeyEntity.setSecretKeyBase64(sharedSecretConverted.sharedSecretBase64());
        temporaryKeyEntity.setTimestampExpires(expirationDate);
        final TemporaryKeyEntity savedEntity = temporaryKeyRepository.save(temporaryKeyEntity);

        // Prepare and return the result
        final SharedSecretResponse sharedSecretResponse = prepareSharedSecretResponse(algorithm, responseCryptogram);
        final TemporaryPublicKeyResponseClaims result = new TemporaryPublicKeyResponseClaims();
        result.setApplicationKey(savedEntity.getAppKey());
        result.setActivationId(savedEntity.getActivationId());
        result.setKeyId(savedEntity.getId());
        result.setSharedSecretResponse(sharedSecretResponse);
        result.setExpiration(savedEntity.getTimestampExpires());
        result.setChallenge(challenge);
        return result;
    }

    private TemporaryKeyResult obtainTemporaryKeyResult(TemporaryPublicKeyRequestClaims requestClaims) throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, GenericServiceException, InvalidKeyException {
        final String applicationKey = requestClaims.getApplicationKey();
        if (applicationKey != null) {
            final ApplicationVersionEntity applicationVersionEntity = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersionEntity == null || !applicationVersionEntity.getSupported()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final String applicationSecret = applicationVersionEntity.getApplicationSecret();
            if (requestClaims.getActivationId() == null) {

                final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationVersionEntity.getApplication().getId());
                final String masterPrivateKeysBase64 = masterKeyPairEntity.getMasterPrivateKeys();
                final EncryptionMode encryptionMode = masterKeyPairEntity.getMasterPrivateKeysEncryption();
                final PrivateKeys masterPrivateKeys = new PrivateKeys(encryptionMode, masterPrivateKeysBase64);
                final PrivateKeyRegistry privateKeyRegistry = masterPrivateKeysConverter.fromDBValue(masterPrivateKeys, applicationVersionEntity.getApplication().getId());
                final PrivateKey privateKey = privateKeyRegistry.getPrivateKey(KeyType.ECDSA_P384)
                        .orElseThrow(() -> localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR));

                final byte[] secretKeyBytes = Base64.getDecoder().decode(applicationSecret);

                final TemporaryKeyResult result = new TemporaryKeyResult();
                result.setSecretKeyBytes(secretKeyBytes);
                result.setPrivateKey(privateKey);
                result.setSharedSecretRequest(requestClaims.getSharedSecretRequest());
                return result;
            } else {

                final Long appId = applicationVersionEntity.getApplication().getRid();

                final Optional<ActivationRecordEntity> activationWithoutLock = activationRepository.findActivationWithoutLock(requestClaims.getActivationId());
                if (activationWithoutLock.isEmpty()) {
                    throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
                }
                final ActivationRecordEntity activation = activationWithoutLock.get();
                if ((activation.getActivationStatus() != ActivationStatus.ACTIVE && activation.getActivationStatus() != ActivationStatus.BLOCKED)
                        || activation.getProtocol() == ActivationProtocol.FIDO2 // FIDO2 does not support temporary keys anywhere
                        || !Objects.equals(appId, activation.getApplication().getRid())) {
                    throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
                }

                final String serverPrivateKeys = activation.getServerPrivateKeys();
                final EncryptionMode encryptionMode = activation.getServerPrivateKeysEncryption();
                final PrivateKeys privateKeys = new PrivateKeys(encryptionMode, serverPrivateKeys);
                final PrivateKeyRegistry privateKeyRegistry = serverPrivateKeysConverter.fromDBValue(privateKeys, activation.getUserId(), activation.getActivationId());
                final PrivateKey serverPrivateKey = privateKeyRegistry.getPrivateKey(KeyType.ECDSA_P384).orElseThrow(() -> localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR));

                final String devicePublicKeys = activation.getDevicePublicKeys();
                final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(devicePublicKeys);
                final PublicKey devicePublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR));
                // TODO - switch to a key derived with KMAC-256 after activation is implemented
                final SecretKey transportKey = SERVER_KEY_FACTORY.deriveTransportKey(serverPrivateKey, devicePublicKey);

                final byte[] applicationSecretKeyBytes = Base64.getDecoder().decode(applicationSecret);
                final SecretKey secretKey = KEY_GENERATOR.deriveSecretKeyHmac(transportKey, applicationSecretKeyBytes);
                final byte[] secretKeyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKey);

                final TemporaryKeyResult result = new TemporaryKeyResult();
                result.setSecretKeyBytes(secretKeyBytes);
                result.setPrivateKey(serverPrivateKey);
                result.setSharedSecretRequest(requestClaims.getSharedSecretRequest());
                return result;
            }
        } else {
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
    }


    private ResponseCryptogram deriveSharedSecret(SharedSecretRequest request, SharedSecretAlgorithm algorithm) throws GenericCryptoException {
        switch (algorithm) {
            case EC_P384 -> {
                final SharedSecretRequestEcdhe requestEcdhe = new SharedSecretRequestEcdhe();
                requestEcdhe.setEcClientPublicKey(request.getEcdhe());
                return SHARED_SECRET_ECDHE.generateResponseCryptogram(requestEcdhe);
            }
            case EC_P384_ML_L3 -> {
                final SharedSecretRequestHybrid requestHybrid = new SharedSecretRequestHybrid();
                requestHybrid.setEcClientPublicKey(request.getEcdhe());
                requestHybrid.setPqcEncapsulationKey(request.getMlkem());
                return SHARED_SECRET_HYBRID.generateResponseCryptogram(requestHybrid);
            }
            default -> throw new IllegalArgumentException("Unsupported shared secret algorithm: " + algorithm);
        }
    }

    private SharedSecretResponse prepareSharedSecretResponse(SharedSecretAlgorithm algorithm, ResponseCryptogram responseCryptogram) {
        final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
        switch (algorithm) {
            case EC_P384 -> {
                final SharedSecretResponseEcdhe sharedSecretResponseEcdhe = (SharedSecretResponseEcdhe) responseCryptogram.getSharedSecretResponse();
                sharedSecretResponse.setEcdhe(sharedSecretResponseEcdhe.getEcServerPublicKey());
                return sharedSecretResponse;
            }
            case EC_P384_ML_L3 -> {
                final SharedSecretResponseHybrid sharedSecretResponseHybrid = (SharedSecretResponseHybrid) responseCryptogram.getSharedSecretResponse();
                sharedSecretResponse.setEcdhe(sharedSecretResponseHybrid.getEcServerPublicKey());
                sharedSecretResponse.setMlkem(sharedSecretResponseHybrid.getPqcEncapsulation());
                return sharedSecretResponse;
            }
            default -> throw new IllegalArgumentException("Unsupported shared secret algorithm: " + algorithm);
        }
    }

}
