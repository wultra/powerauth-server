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

package com.wultra.security.powerauth.app.server.database.model;

import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.Getter;

import java.security.PrivateKey;
import java.util.*;

/**
 * Registry for storing private keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
public class PrivateKeyRegistry {

    final Map<SharedSecretAlgorithm, Map<KeyType, PrivateKey>> privateKeys = new LinkedHashMap<>();

    /**
     * Get a private key for given algorithm and key type.
     * @param algorithm Shared secret algorithm.
     * @param keyType Key type.
     * @return Optional private key.
     */
    public Optional<PrivateKey> getPrivateKey(SharedSecretAlgorithm algorithm, KeyType keyType) {
        return Optional.ofNullable(privateKeys.get(algorithm))
                .map(keysByKeyTypes -> keysByKeyTypes.get(keyType));
    }

    /**
     * Store a private key for given algorithm and key type.
     * @param algorithm Shared secret algorithm.
     * @param keyType Key type.
     * @param key Private key to store.
     */
    public void storePrivateKey(SharedSecretAlgorithm algorithm, KeyType keyType, PrivateKey key) {
        privateKeys.computeIfAbsent(algorithm, k -> new LinkedHashMap<>())
                .put(keyType, key);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PrivateKeyRegistry that = (PrivateKeyRegistry) o;
        return Objects.equals(privateKeys, that.privateKeys);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(privateKeys);
    }

    @Override
    public String toString() {
        return "PrivateKeyRegistry";
    }

}
