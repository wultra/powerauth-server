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
 *
 */
package com.wultra.security.powerauth.app.server.converter;

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.crypto.KeyProvider;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Converter building the map of device public keys exposed on activation read APIs.
 * <p>
 * The map is keyed by {@link KeyType} name and the values are the normalized Base64 representations
 * byte-identical to the stored {@code key_data}. Protocol v4 keys are read from the device public key
 * registry; for protocol v3 the single legacy key is returned under {@link KeyType#ECDSA_P256}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
@Component
public class DevicePublicKeysConverter {

    private final KeyProvider keyProvider;
    private final ObjectMapper publicKeyObjectMapper;

    /**
     * Converter constructor.
     * @param keyProvider Provider of device public keys stored for an activation.
     * @param publicKeyObjectMapper Object mapper serializing public keys to normalized Base64.
     */
    public DevicePublicKeysConverter(final KeyProvider keyProvider,
                                     @Qualifier("publicKeyObjectMapper") final ObjectMapper publicKeyObjectMapper) {
        this.keyProvider = keyProvider;
        this.publicKeyObjectMapper = publicKeyObjectMapper;
    }

    /**
     * Build the map of device public keys for the given activation.
     * <p>
     * A v4 activation exposes only the registry keys that belong to its crypto algorithm (the registry may
     * still hold obsolete keys of an earlier, retried upgrade), and never falls back to the legacy key.
     * Older activations expose the single legacy v3 key. The map is empty when no device public key has been
     * exchanged yet (e.g. an activation in the CREATED state), when the stored keys cannot be converted, or
     * when a v4 activation lacks one of the keys required by its algorithm, so that one corrupted row does
     * not fail the whole read API and a partial key set is never mistaken for an EC-only activation.
     *
     * @param activation Activation whose device public keys to expose.
     * @return Map of {@link KeyType} name to normalized Base64 public key, never {@code null}.
     */
    public Map<String, String> toDevicePublicKeys(final ActivationRecordEntity activation) {
        if (Integer.valueOf(4).equals(activation.getVersion())) {
            return toRegistryDevicePublicKeys(activation);
        }

        final Map<String, String> result = new LinkedHashMap<>();
        final String legacyDevicePublicKeyBase64 = activation.getDevicePublicKeyBase64();
        if (legacyDevicePublicKeyBase64 != null) {
            result.put(KeyType.ECDSA_P256.name(), legacyDevicePublicKeyBase64);
        }
        return result;
    }

    private Map<String, String> toRegistryDevicePublicKeys(final ActivationRecordEntity activation) {
        try {
            final Optional<PublicKeyRegistry> registry = keyProvider.getDevicePublicKeys(activation);
            if (registry.isEmpty()) {
                if (activation.getActivationStatus() != ActivationStatus.CREATED && activation.getActivationStatus() != ActivationStatus.REMOVED) {
                    logger.warn("No device public keys stored for the v4 activation, returning none, activationId={}, activationStatus={}",
                            activation.getActivationId(), activation.getActivationStatus());
                }
                return new LinkedHashMap<>();
            }
            final Map<String, String> storedKeys = publicKeyObjectMapper.convertValue(
                    registry.get().getPublicKeys(), new TypeReference<Map<String, String>>() {});
            final List<KeyType> expectedKeyTypes = expectedKeyTypes(activation.getCryptoAlgorithm());
            if (expectedKeyTypes.isEmpty()) {
                return storedKeys;
            }
            final Map<String, String> keys = new LinkedHashMap<>();
            for (final KeyType keyType : expectedKeyTypes) {
                final String key = storedKeys.get(keyType.name());
                if (key == null) {
                    logger.error("Device public keys are incomplete for the activation algorithm, returning none, activationId={}, cryptoAlgorithm={}",
                            activation.getActivationId(), activation.getCryptoAlgorithm());
                    return new LinkedHashMap<>();
                }
                keys.put(keyType.name(), key);
            }
            return keys;
        } catch (GenericServiceException | RuntimeException ex) {
            logger.error("Device public keys cannot be converted, returning none, activationId={}", activation.getActivationId(), ex);
            return new LinkedHashMap<>();
        }
    }

    /**
     * Key types a v4 activation of the given algorithm holds, empty when the algorithm does not define them.
     */
    private static List<KeyType> expectedKeyTypes(final SharedSecretAlgorithm algorithm) {
        if (algorithm == null) {
            return List.of();
        }
        return switch (algorithm) {
            case EC_P384 -> List.of(KeyType.ECDSA_P384);
            case EC_P384_ML_L3 -> List.of(KeyType.ECDSA_P384, KeyType.MLDSA_65);
            case EC_P384_ML_L5 -> List.of(KeyType.ECDSA_P384, KeyType.MLDSA_87);
            default -> List.of();
        };
    }

}
