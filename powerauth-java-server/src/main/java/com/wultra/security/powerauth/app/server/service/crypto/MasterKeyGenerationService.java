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
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;

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
                // Migration to V4 registries
                privateKeyRegistry = new PrivateKeyRegistry();
                publicKeyRegistry = new PublicKeyRegistry();
            } else {
                // Update existing V4 keypairs
                privateKeyRegistry = loadPrivateRegistryFromEntity(keyPair, application);
                publicKeyRegistry = loadPublicRegistryFromEntity(keyPair);
            }

            generateAndStoreV4KeyPairs(privateKeyRegistry, publicKeyRegistry);
            writeRegistriesToEntity(keyPair, privateKeyRegistry, publicKeyRegistry, application);
            masterKeyPairRepository.save(keyPair);

        } catch (CryptoProviderException e) {
            logger.error("Could not generate keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    private MasterKeyPairEntity findMasterKeyPair(ApplicationEntity application) {
        return masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
    }

    private MasterKeyPairEntity createInitialV3Entity(ApplicationEntity app) throws CryptoProviderException, GenericServiceException {
        final KeyPair kp = SERVER_ACTIVATION_V3.generateServerKeyPair();
        final PrivateKey privateKey = kp.getPrivate();
        final PublicKey publicKey = kp.getPublic();

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

        entity.setMasterKeyPrivateBase64(Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPrivateKeyToBytes(privateKey)));
        entity.setMasterKeyPublicBase64(Base64.getEncoder().encodeToString(KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P256, publicKey)));

        return entity;
    }

    private PrivateKeyRegistry loadPrivateRegistryFromEntity(MasterKeyPairEntity entity, ApplicationEntity app) throws GenericServiceException {
        PrivateKeys privateKeys = new PrivateKeys(entity.getMasterPrivateKeysEncryption(), entity.getMasterPrivateKeys());
        return masterPrivateKeysConverter.fromDBValue(privateKeys, app.getId());
    }

    private PublicKeyRegistry loadPublicRegistryFromEntity(MasterKeyPairEntity entity) throws GenericServiceException {
        return publicKeysConverter.fromDBValue(entity.getMasterPublicKeys());
    }

    private void generateAndStoreV4KeyPairs(PrivateKeyRegistry privateKeyRegistry, PublicKeyRegistry publicKeyRegistry) throws CryptoProviderException {
        KeyPair ec = SERVER_ACTIVATION_V4.generateEcServerKeyPair();
        privateKeyRegistry.storePrivateKey(KeyType.ECDSA_P384, ec.getPrivate());
        publicKeyRegistry.storePublicKey(KeyType.ECDSA_P384, ec.getPublic());

        KeyPair pqcDsa = SERVER_ACTIVATION_V4.generatePqcServerKeyPair();
        privateKeyRegistry.storePrivateKey(KeyType.MLDSA_65, pqcDsa.getPrivate());
        publicKeyRegistry.storePublicKey(KeyType.MLDSA_65, pqcDsa.getPublic());
    }

    private void writeRegistriesToEntity(MasterKeyPairEntity entity, PrivateKeyRegistry privateKeyRegistry,
                                         PublicKeyRegistry publicKeyRegistry, ApplicationEntity app) throws GenericServiceException {
        PrivateKeys masterPrivateKeys = masterPrivateKeysConverter.toDBValue(privateKeyRegistry, app.getId());
        entity.setMasterPrivateKeys(masterPrivateKeys.privateKeysBase64());
        entity.setMasterPrivateKeysEncryption(masterPrivateKeys.encryptionMode());
        entity.setMasterPublicKeys(publicKeysConverter.toDBValue(publicKeyRegistry));
    }

}
