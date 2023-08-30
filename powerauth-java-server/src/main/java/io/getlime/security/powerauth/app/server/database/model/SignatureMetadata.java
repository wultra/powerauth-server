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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.getlime.security.powerauth.app.server.database.model.enumeration.SignatureMetadataType;

/**
 * Represents a generic interface for metadata related to different types of signatures.
 * The interface allows for defining various metadata attributes as type parameters T1 and T2.
 *
 * @param <T1> The type of the first metadata parameter.
 * @param <T2> The type of the second metadata parameter.
 * @author Jan Dusil
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = PowerAuthSignatureMetadata.class,
                name = SignatureMetadataType.POWER_AUTH)
})
public interface SignatureMetadata<T1, T2> {

    /**
     * Retrieves the first metadata parameter.
     *
     * @return The first metadata parameter.
     */
    @JsonIgnore
    T1 getMetadataParam1();

    /**
     * Sets the value for the first metadata parameter.
     *
     * @param metadataParam1 The value to set.
     */
    @JsonIgnore
    void setMetadataParam1(T1 metadataParam1);

    /**
     * Retrieves the second metadata parameter.
     *
     * @return The second metadata parameter.
     */
    @JsonIgnore
    T2 getMetadataParam2();

    /**
     * Sets the value for the second metadata parameter.
     *
     * @param metadataParam2 The value to set.
     */
    @JsonIgnore
    void setMetadataParam2(T2 metadataParam2);
}

