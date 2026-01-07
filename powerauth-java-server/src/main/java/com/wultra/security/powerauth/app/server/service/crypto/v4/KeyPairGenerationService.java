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

import com.wultra.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import com.wultra.security.powerauth.app.server.database.model.*;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.crypto.KeyProvider;
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
import java.util.Base64;

/**
 * Service for generating server key pairs.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class KeyPairGenerationService {

    private final LocalizationProvider localizationProvider;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final KeyProvider keyProvider;

    private final com.wultra.security.powerauth.crypto.server.activation.PowerAuthServerActivation SERVER_ACTIVATION_V3 = new com.wultra.security.powerauth.crypto.server.activation.PowerAuthServerActivation();
    private final com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation SERVER_ACTIVATION_V4 = new com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation();

    private final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Generate and persist a new key pair associated with the given activation.
     * @param activation Activation record for which the server key pair is generated.
     * @param algorithm Algorithm for which the keys should be generated.
     */
    public void generateServerKeyPairs(ActivationRecordEntity activation, SharedSecretAlgorithm algorithm) throws GenericServiceException {
        try {
            if (algorithm == SharedSecretAlgorithm.EC_P256) {
                // Generate keypair for V3 algorithm only
                generateAndStoreServerKeyPairEcP256(activation);
                return;
            }

            // Handle V4 algorithms
            final PublicKeyRegistry serverPublicKeys = new PublicKeyRegistry();
            final PrivateKeyRegistry serverPrivateKeys = new PrivateKeyRegistry();

            switch (algorithm) {
                case EC_P384 -> generateServerKeyPairEcP384(serverPublicKeys, serverPrivateKeys);
                case EC_P384_ML_L3 -> {
                    generateServerKeyPairEcP384(serverPublicKeys, serverPrivateKeys);
                    generateServerKeyPairMlDsa65(serverPublicKeys, serverPrivateKeys);
                }
                case EC_P384_ML_L5 -> {
                    generateServerKeyPairEcP384(serverPublicKeys, serverPrivateKeys);
                    generateServerKeyPairMlDsa87(serverPublicKeys, serverPrivateKeys);
                }
                case ML_L3 -> generateServerKeyPairMlDsa65(serverPublicKeys, serverPrivateKeys);
                case ML_L5 -> generateServerKeyPairMlDsa87(serverPublicKeys, serverPrivateKeys);
                default -> throw new IllegalArgumentException("Unsupported shared secret algorithm: " + algorithm);
            }

            keyProvider.storeServerPublicKeys(activation, serverPublicKeys);
            keyProvider.storeServerPrivateKeys(activation, serverPrivateKeys);
        } catch (Exception e) {
            logger.error("Could not generate keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    private void generateAndStoreServerKeyPairEcP256(ActivationRecordEntity activation) throws CryptoProviderException, GenericServiceException {
        final KeyPair serverKeyPair = SERVER_ACTIVATION_V3.generateServerKeyPair();

        final byte[] serverKeyPrivateBytes = KEY_CONVERTOR.convertPrivateKeyToBytes(serverKeyPair.getPrivate());
        final byte[] serverKeyPublicBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, serverKeyPair.getPublic());

        activation.setServerPublicKeyBase64(Base64.getEncoder().encodeToString(serverKeyPublicBytes));

        final ServerPrivateKeyRecord serverPrivateKey = serverPrivateKeyConverter.toDBValue(serverKeyPrivateBytes, activation.getUserId(), activation.getActivationId());
        activation.setServerPrivateKeyEncryption(serverPrivateKey.encryptionAlgorithm());
        activation.setServerPrivateKeyBase64(serverPrivateKey.serverPrivateKeyBase64());
    }

    private void generateServerKeyPairEcP384(PublicKeyRegistry serverPublicKeys, PrivateKeyRegistry serverPrivateKeys) throws CryptoProviderException {
        final KeyPair serverKeyPairEc = SERVER_ACTIVATION_V4.generateEcServerKeyPair();
        serverPublicKeys.storePublicKey(KeyType.ECDSA_P384, serverKeyPairEc.getPublic());
        serverPrivateKeys.storePrivateKey(KeyType.ECDSA_P384, serverKeyPairEc.getPrivate());
    }

    private void generateServerKeyPairMlDsa65(PublicKeyRegistry serverPublicKeys, PrivateKeyRegistry serverPrivateKeys) throws GenericCryptoException, CryptoProviderException {
        final KeyPair serverKeyPairPqcMlDsa65 = SERVER_ACTIVATION_V4.generatePqcServerKeyPair(SharedSecretAlgorithm.ML_L3);
        serverPublicKeys.storePublicKey(KeyType.MLDSA_65, serverKeyPairPqcMlDsa65.getPublic());
        serverPrivateKeys.storePrivateKey(KeyType.MLDSA_65, serverKeyPairPqcMlDsa65.getPrivate());
    }

    private void generateServerKeyPairMlDsa87(PublicKeyRegistry serverPublicKeys, PrivateKeyRegistry serverPrivateKeys) throws GenericCryptoException, CryptoProviderException {
        final KeyPair serverKeyPairPqcMlDsa87 = SERVER_ACTIVATION_V4.generatePqcServerKeyPair(SharedSecretAlgorithm.ML_L5);
        serverPublicKeys.storePublicKey(KeyType.MLDSA_87, serverKeyPairPqcMlDsa87.getPublic());
        serverPrivateKeys.storePrivateKey(KeyType.MLDSA_87, serverKeyPairPqcMlDsa87.getPrivate());
    }

}
