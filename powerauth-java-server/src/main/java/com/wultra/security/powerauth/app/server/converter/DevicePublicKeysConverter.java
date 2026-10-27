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
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.crypto.KeyProvider;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
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
     * Returns the v4 registry keys when present, otherwise falls back to the legacy v3 key. The map is
     * empty when no device public key has been exchanged yet (e.g. an activation in the CREATED state)
     * or when the stored keys cannot be converted, so that one corrupted row does not fail the whole read API.
     *
     * @param activation Activation whose device public keys to expose.
     * @return Map of {@link KeyType} name to normalized Base64 public key, never {@code null}.
     */
    public Map<String, String> toDevicePublicKeys(final ActivationRecordEntity activation) {
        final Optional<PublicKeyRegistry> registry;
        try {
            registry = keyProvider.getDevicePublicKeys(activation);
            if (registry.isPresent()) {
                return publicKeyObjectMapper.convertValue(
                        registry.get().getPublicKeys(), new TypeReference<Map<String, String>>() {});
            }
        } catch (GenericServiceException | RuntimeException ex) {
            logger.error("Device public keys cannot be converted, returning none, activationId={}", activation.getActivationId(), ex);
            return new LinkedHashMap<>();
        }

        final Map<String, String> result = new LinkedHashMap<>();
        final String legacyDevicePublicKeyBase64 = activation.getDevicePublicKeyBase64();
        if (legacyDevicePublicKeyBase64 != null) {
            result.put(KeyType.ECDSA_P256.name(), legacyDevicePublicKeyBase64);
        }
        return result;
    }

}
