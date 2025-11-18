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

package com.wultra.security.powerauth.app.server.service.encryption;

import java.util.List;
import java.util.function.Supplier;

/**
 * Default encryption key supplier for database per-record encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class DefaultEncryptionKeySupplier implements EncryptionKeySupplier{

    private final Supplier<List<String>> keyDerivationData;
    private final Supplier<List<String>> associatedData;

    /**
     * Encryption key supplier constructor.
     * @param keyDerivationData Data used for key derivation.
     * @param associatedData Associated data.
     */
    public DefaultEncryptionKeySupplier(List<String> keyDerivationData, List<String> associatedData) {
        this.keyDerivationData = () -> List.copyOf(keyDerivationData);
        this.associatedData = () -> List.copyOf(associatedData);
    }

    @Override
    public Supplier<List<String>> keyDerivationData() {
        return keyDerivationData;
    }

    @Override
    public Supplier<List<String>> associatedData() {
        return associatedData;
    }

}
