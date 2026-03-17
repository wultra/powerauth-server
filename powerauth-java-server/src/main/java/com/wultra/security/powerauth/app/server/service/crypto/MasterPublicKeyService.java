/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.MasterPublicKeys;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.function.ThrowingFunction;

import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

/**
 * Service responsible for extracting master public keys from a {@link MasterKeyPairEntity}
 * based on the set of supported algorithms for an application.
 *
 * @author Vit Kotacka
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class MasterPublicKeyService {

    private final PublicKeysConverter publicKeysConverter;

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    /**
     * Extracts the master public keys from the given key pair entity for the provided supported algorithms.
     *
     * @param masterKeyPair      Master key pair entity.
     * @param supportedAlgorithms List of algorithms supported by the application.
     * @return Record containing the (possibly {@code null}) public keys for each algorithm.
     */
    public MasterPublicKeys extractPublicKeys(final MasterKeyPairEntity masterKeyPair, final List<SharedSecretAlgorithm> supportedAlgorithms) throws GenericServiceException {
        final String publicKeyP256 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P256)
                ? masterKeyPair.getMasterKeyPublicBase64()
                : null;

        String publicKeyP384 = null;
        String publicKeyMlDsa65 = null;
        String publicKeyMlDsa87 = null;

        if (masterKeyPair.getMasterPublicKeys() != null) {
            final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(masterKeyPair.getMasterPublicKeys());
            final boolean supportsEcP384 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384);
            final boolean supportsEcP384MlL3 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L3);
            final boolean supportsEcP384MlL5 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L5);

            if (supportsEcP384 || supportsEcP384MlL3 || supportsEcP384MlL5) {
                publicKeyP384 = convertPublicKeyToBase64(publicKeyRegistry, KeyType.ECDSA_P384,
                        pk -> KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, pk));
            }
            if (supportsEcP384MlL3) {
                publicKeyMlDsa65 = convertPublicKeyToBase64(publicKeyRegistry, KeyType.MLDSA_65,
                        KEY_CONVERTOR_PQC_DSA::convertPublicKeyToBytes);
            }
            if (supportsEcP384MlL5) {
                publicKeyMlDsa87 = convertPublicKeyToBase64(publicKeyRegistry, KeyType.MLDSA_87,
                        KEY_CONVERTOR_PQC_DSA::convertPublicKeyToBytes);
            }
        }

        return new MasterPublicKeys(publicKeyP256, publicKeyP384, publicKeyMlDsa65, publicKeyMlDsa87);
    }

    private String convertPublicKeyToBase64(final PublicKeyRegistry registry, final KeyType keyType, final ThrowingFunction<PublicKey, byte[]> converter) {
        return registry.getPublicKey(keyType)
                .map(publicKey -> {
                    try {
                        return Base64.getEncoder().encodeToString(converter.apply(publicKey));
                    } catch (Exception e) {
                        logger.warn("Public key conversion failed for {}: {}", keyType, e.getMessage());
                        return null;
                    }
                })
                .orElse(null);
    }

}
