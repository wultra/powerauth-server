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

import lombok.Getter;
import lombok.ToString;

import java.security.PublicKey;
import java.util.*;

/**
 * Registry for storing public keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
@ToString
public class PublicKeyRegistry {

    final Map<KeyType, PublicKey> publicKeys = new LinkedHashMap<>();

    /**
     * Get a public key for given algorithm and key type.
     * @param keyType Key type.
     * @return Optional public key.
     */
    public Optional<PublicKey> getPublicKey(KeyType keyType) {
        return Optional.ofNullable(publicKeys.get(keyType));
    }

    /**
     * Store a public key for given algorithm and key type.
     * @param keyType Key type.
     * @param publicKey Public key to store.
     */
    public void storePublicKey(KeyType keyType, PublicKey publicKey) {
        publicKeys.put(keyType, publicKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyRegistry that = (PublicKeyRegistry) o;
        return Objects.equals(publicKeys, that.publicKeys);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(publicKeys);
    }

}
