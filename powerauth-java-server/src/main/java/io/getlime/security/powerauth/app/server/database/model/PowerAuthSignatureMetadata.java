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
import lombok.NoArgsConstructor;


/**
 * Concrete implementation of the SignatureMetadata interface for PowerAuth.
 * Contains metadata parameters specific to PowerAuth Signature.
 *
 * @author Jan Dusil
 */
@AllArgsConstructor
@NoArgsConstructor
public class PowerAuthSignatureMetadata implements SignatureMetadata<String, String> {

    @JsonProperty("signatureDataMethod")
    private String signatureDataMethod;
    @JsonProperty("signatureDataUriId")
    private String signatureDataUriId;

    /**
     * Retrieves the signature method.
     *
     * @return The signature method.
     */
    @Override
    public String getMetadataParam1() {
        return signatureDataMethod;
    }

    /**
     * Sets the value for the signature method.
     *
     * @param metadataParam1 The value to set.
     */
    @Override
    public void setMetadataParam1(String metadataParam1) {
        this.signatureDataMethod = metadataParam1;
    }

    /**
     * Retrieves the URI ID related to the signature.
     *
     * @return The URI ID.
     */
    @Override
    public String getMetadataParam2() {
        return signatureDataUriId;
    }

    /**
     * Sets the value for the URI ID related to the signature.
     *
     * @param metadataParam2 The value to set.
     */
    @Override
    public void setMetadataParam2(String metadataParam2) {
        this.signatureDataUriId = metadataParam2;
    }
}
