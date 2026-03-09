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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.SdkConfiguration;
import com.wultra.security.powerauth.app.server.service.util.SdkConfigurationSerializer;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.util.function.ThrowingFunction;

import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

/**
 * Abstract Behavior class implementing application and application
 * detail endpoints for all the subsequent version.
 *
 * @author Vít Kotačka, vit.kotacka@wultra.com
 */
@AllArgsConstructor
@Slf4j(access = AccessLevel.PROTECTED)
@SuperBuilder
public class AbstractApplicationServiceBehavior {

    private final PublicKeysConverter publicKeysConverter;
    private final SdkConfigurationSerializer sdkConfigurationSerializer;
    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    protected static @NonNull ApplicationVersion getApplicationVersion(ApplicationVersionEntity version, String sdkConfigSerialized) {
        final ApplicationVersion ver = new ApplicationVersion();
        ver.setApplicationVersionId(version.getId());
        ver.setApplicationKey(version.getApplicationKey());
        ver.setApplicationSecret(version.getApplicationSecret());
        ver.setMobileSdkConfig(sdkConfigSerialized);
        ver.setSupported(version.getSupported());

        return ver;
    }

    /**
     * Converts a public key from the registry to a Base64-encoded string.
     *
     * @param registry  Public key registry.
     * @param keyType   Key type.
     * @param converter Key converter function with possible exception.
     * @return Base-64 encoded public key.
     */
    protected String convertPublicKeyToBase64(PublicKeyRegistry registry, KeyType keyType, ThrowingFunction<PublicKey, byte[]> converter) {
        return registry.getPublicKey(keyType)
                .map(publicKey -> {
                    try {
                        final byte[] bytes = converter.apply(publicKey);
                        return Base64.getEncoder().encodeToString(bytes);
                    } catch (Exception e) {
                        AbstractApplicationDetailServiceBehavior.logger.warn("Public key conversion failed for {}: {}", keyType, e.getMessage());
                        return null;
                    }
                })
                .orElse(null);
    }

    @NonNull
    protected Result getResult(MasterKeyPairEntity keyPair, List<SharedSecretAlgorithm> supportedAlgorithms) throws GenericServiceException {
        String publicKeyP384 = null;
        String publicKeyMlDsa65 = null;
        String publicKeyMlDsa87 = null;

        if (keyPair.getMasterPublicKeys() != null) {
            final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(keyPair.getMasterPublicKeys());

            final boolean supportsEcP384 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384);
            final boolean supportsEcP384MlL3 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L3);
            final boolean supportsEcP384MlL5 = supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L5);

            if (supportsEcP384 || supportsEcP384MlL3 || supportsEcP384MlL5) {
                publicKeyP384 = convertPublicKeyToBase64(
                        publicKeyRegistry,
                        KeyType.ECDSA_P384,
                        publicKey -> KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, publicKey)
                );
            }
            if (supportsEcP384MlL3) {
                publicKeyMlDsa65 = convertPublicKeyToBase64(
                        publicKeyRegistry,
                        KeyType.MLDSA_65,
                        KEY_CONVERTOR_PQC_DSA::convertPublicKeyToBytes
                );
            }
            if (supportsEcP384MlL5) {
                publicKeyMlDsa87 = convertPublicKeyToBase64(
                        publicKeyRegistry,
                        KeyType.MLDSA_87,
                        KEY_CONVERTOR_PQC_DSA::convertPublicKeyToBytes
                );
            }
        }

        return new Result(publicKeyP384, publicKeyMlDsa65, publicKeyMlDsa87);
    }

    protected String getSdkConfigSerialized(ApplicationVersionEntity version, String publicKeyP256, Result result) throws GenericServiceException {
        final SdkConfiguration sdkConfig = SdkConfiguration.builder()
                .appKey(version.getApplicationKey())
                .appSecret(version.getApplicationSecret())
                .masterPublicKeyP256(publicKeyP256)
                .masterPublicKeyP384(result.publicKeyP384())
                .masterPublicKeyMlDsa65(result.publicKeyMlDsa65())
                .masterPublicKeyMlDsa87(result.publicKeyMlDsa87())
                .build();

        return sdkConfigurationSerializer.serialize(sdkConfig);
    }

    protected record Result(String publicKeyP384, String publicKeyMlDsa65, String publicKeyMlDsa87) {
    }
}