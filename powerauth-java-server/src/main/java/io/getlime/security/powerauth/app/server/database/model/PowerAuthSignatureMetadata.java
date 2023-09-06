/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.database.model;

import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;


/**
 * Concrete implementation of the {@link SignatureMetadata} interface for PowerAuth.
 * Contains metadata parameters specific to PowerAuth Signature.
 *
 * @author Jan Dusil
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
public class PowerAuthSignatureMetadata implements SignatureMetadata, Serializable {

    @JsonProperty("signatureDataMethod")
    private String signatureDataMethod;
    @JsonProperty("signatureDataUriId")
    private String signatureDataUriId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PowerAuthSignatureMetadata that = (PowerAuthSignatureMetadata) o;
        return Objects.equals(signatureDataMethod, that.signatureDataMethod) &&
                Objects.equals(signatureDataUriId, that.signatureDataUriId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signatureDataMethod, signatureDataUriId);
    }
}
