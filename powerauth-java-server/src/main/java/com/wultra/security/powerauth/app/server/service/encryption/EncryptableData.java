/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.encryption;

import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import org.apache.commons.lang3.ArrayUtils;

import java.util.Arrays;
import java.util.Objects;

/**
 * A wrapper for data encryption, keeping both the mode and the data.
 *
 * @param encryptionAlgorithm Encryption mode. Determine format of {@link #encryptedData()}.
 * @param encryptedData Data. May be plain or encrypted. Depends on {@link #encryptionAlgorithm()}.
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public record EncryptableData(EncryptionAlgorithm encryptionAlgorithm, byte[] encryptedData) {
    @Override
    public String toString() {
        return "EncryptableRecord{" +
                "encryptionAlgorithm=" + encryptionAlgorithm +
                ", encryptedDataLength=" + ArrayUtils.getLength(encryptedData) +
                '}';
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof final EncryptableData that)) {
            return false;
        }
        return Objects.deepEquals(encryptedData, that.encryptedData) && encryptionAlgorithm == that.encryptionAlgorithm;
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptionAlgorithm, Arrays.hashCode(encryptedData));
    }
}
