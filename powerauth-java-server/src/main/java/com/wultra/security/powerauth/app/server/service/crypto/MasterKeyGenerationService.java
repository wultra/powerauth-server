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

package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.converter.MasterPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeys;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Service for generating master server keys for applications.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class MasterKeyGenerationService {

    private final MasterKeyPairRepository masterKeyPairRepository;
    private final LocalizationProvider localizationProvider;
    private final MasterPrivateKeysConverter masterPrivateKeysConverter;
    private final PublicKeysConverter publicKeysConverter;
    private final AlgorithmQueryService algorithmQueryService;

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();

    private final com.wultra.security.powerauth.crypto.server.activation.PowerAuthServerActivation SERVER_ACTIVATION_V3 = new com.wultra.security.powerauth.crypto.server.activation.PowerAuthServerActivation();
    private final com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation SERVER_ACTIVATION_V4 = new com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation();

    /**
     * Generate master server key pairs for application.
     * @param application Application.
     * @throws GenericServiceException Thrown in case of a cryptography error.
     */
    public void generateMasterKeyPairs(ApplicationEntity application) throws GenericServiceException {
        try {
            MasterKeyPairEntity keyPair = findMasterKeyPair(application);

            final PrivateKeyRegistry privateKeyRegistry;
            final PublicKeyRegistry publicKeyRegistry;

            if (keyPair == null) {
                // Initialize keypair
                keyPair = createInitialV3Entity(application);
                privateKeyRegistry = new PrivateKeyRegistry();
                publicKeyRegistry = new PublicKeyRegistry();
                writeRegistriesToEntity(keyPair, privateKeyRegistry, publicKeyRegistry, application);
            } else if (keyPair.getMasterPrivateKeys() == null) {
                // Create new V4 keypair registries
                privateKeyRegistry = new PrivateKeyRegistry();
                publicKeyRegistry = new PublicKeyRegistry();
            } else {
                // Update existing V4 keypair registries
                privateKeyRegistry = loadPrivateRegistryFromEntity(keyPair, application);
                publicKeyRegistry = loadPublicRegistryFromEntity(keyPair);
            }

            final List<SharedSecretAlgorithm> supportedAlgorithms = algorithmQueryService.getSupportedAlgorithms(application);
            generateAndStoreV3KeyPair(keyPair, supportedAlgorithms);
            generateAndStoreV4KeyPairs(privateKeyRegistry, publicKeyRegistry, supportedAlgorithms);
            writeRegistriesToEntity(keyPair, privateKeyRegistry, publicKeyRegistry, application);
            masterKeyPairRepository.save(keyPair);

        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Could not generate keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    private MasterKeyPairEntity findMasterKeyPair(ApplicationEntity application) {
        return masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
    }

    private MasterKeyPairEntity createInitialV3Entity(ApplicationEntity app) throws CryptoProviderException, GenericServiceException {
        MasterKeyPairEntity entity = new MasterKeyPairEntity();
        entity.setTimestampCreated(new Date());
        entity.setName(app.getId() + " Default Keypair");
        entity.setApplication(app);

        // Initialize empty V4 registries into DB fields
        PrivateKeyRegistry privateKeyRegistry = new PrivateKeyRegistry();
        PublicKeyRegistry publicKeyRegistry = new PublicKeyRegistry();
        PrivateKeys masterPrivateKeys = masterPrivateKeysConverter.toDBValue(privateKeyRegistry, app.getId());
        entity.setMasterPrivateKeys(masterPrivateKeys.privateKeysBase64());
        entity.setMasterPrivateKeysEncryption(masterPrivateKeys.encryptionMode());
        entity.setMasterPublicKeys(publicKeysConverter.toDBValue(publicKeyRegistry));
        return entity;
    }

    private void generateAndStoreV3KeyPair(MasterKeyPairEntity keyPairEntity, List<SharedSecretAlgorithm> supportedAlgorithms) throws CryptoProviderException {
        if (!supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P256)) {
            return;
        }

        if (keyPairEntity.getMasterKeyPrivateBase64() != null && keyPairEntity.getMasterKeyPublicBase64() != null) {
            return;
        }

        final KeyPair kp = SERVER_ACTIVATION_V3.generateServerKeyPair();
        final PrivateKey privateKey = kp.getPrivate();
        final PublicKey publicKey = kp.getPublic();

        keyPairEntity.setMasterKeyPrivateBase64(Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPrivateKeyToBytes(privateKey)));
        keyPairEntity.setMasterKeyPublicBase64(Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P256, publicKey)));
    }

    private PrivateKeyRegistry loadPrivateRegistryFromEntity(MasterKeyPairEntity entity, ApplicationEntity app) throws GenericServiceException {
        PrivateKeys privateKeys = new PrivateKeys(entity.getMasterPrivateKeysEncryption(), entity.getMasterPrivateKeys());
        return masterPrivateKeysConverter.fromDBValue(privateKeys, app.getId());
    }

    private PublicKeyRegistry loadPublicRegistryFromEntity(MasterKeyPairEntity entity) throws GenericServiceException {
        return publicKeysConverter.fromDBValue(entity.getMasterPublicKeys());
    }

    private void generateAndStoreV4KeyPairs(PrivateKeyRegistry privateKeyRegistry, PublicKeyRegistry publicKeyRegistry, List<SharedSecretAlgorithm> supportedAlgorithms) throws CryptoProviderException, GenericCryptoException {
        if (supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384)
                || supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L3)
                || supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L5)) {
            if (privateKeyRegistry.getPrivateKey(KeyType.ECDSA_P384).isEmpty() || publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).isEmpty()) {
                KeyPair ec = SERVER_ACTIVATION_V4.generateEcServerKeyPair();
                privateKeyRegistry.storePrivateKey(KeyType.ECDSA_P384, ec.getPrivate());
                publicKeyRegistry.storePublicKey(KeyType.ECDSA_P384, ec.getPublic());
            }
        }

        // Algorithm ML_L3 is not supported yet
        if (supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L3)) {
            if (privateKeyRegistry.getPrivateKey(KeyType.MLDSA_65).isEmpty() || publicKeyRegistry.getPublicKey(KeyType.MLDSA_65).isEmpty()) {
                KeyPair pqcDsa65 = SERVER_ACTIVATION_V4.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L3);
                privateKeyRegistry.storePrivateKey(KeyType.MLDSA_65, pqcDsa65.getPrivate());
                publicKeyRegistry.storePublicKey(KeyType.MLDSA_65, pqcDsa65.getPublic());
            }
        }

        // Algorithm ML_L5 is not supported yet
        if (supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L5)) {
            if (privateKeyRegistry.getPrivateKey(KeyType.MLDSA_87).isEmpty() || publicKeyRegistry.getPublicKey(KeyType.MLDSA_87).isEmpty()) {
                KeyPair pqcDsa87 = SERVER_ACTIVATION_V4.generatePqcServerKeyPair(SharedSecretAlgorithm.EC_P384_ML_L5);
                privateKeyRegistry.storePrivateKey(KeyType.MLDSA_87, pqcDsa87.getPrivate());
                publicKeyRegistry.storePublicKey(KeyType.MLDSA_87, pqcDsa87.getPublic());
            }
        }
    }

    private void writeRegistriesToEntity(MasterKeyPairEntity entity, PrivateKeyRegistry privateKeyRegistry,
                                         PublicKeyRegistry publicKeyRegistry, ApplicationEntity app) throws GenericServiceException {
        PrivateKeys masterPrivateKeys = masterPrivateKeysConverter.toDBValue(privateKeyRegistry, app.getId());
        entity.setMasterPrivateKeys(masterPrivateKeys.privateKeysBase64());
        entity.setMasterPrivateKeysEncryption(masterPrivateKeys.encryptionMode());
        entity.setMasterPublicKeys(publicKeysConverter.toDBValue(publicKeyRegistry));
    }

}
