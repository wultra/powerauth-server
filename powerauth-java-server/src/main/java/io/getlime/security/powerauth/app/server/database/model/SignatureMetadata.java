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

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.getlime.security.powerauth.app.server.database.model.enumeration.SignatureMetadataType;

import java.io.Serializable;

/**
 * Represents an interface for metadata related to different types of signatures.
 * The interface is designed to work specifically with metadata attributes of type
 * String for the first parameter and Object for the second parameter. This allows
 * the flexibility to capture various metadata details according to the specific
 * requirements of different signature algorithms or methods.
 *
 * @author Jan Dusil
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = PowerAuthSignatureMetadata.class,
                name = SignatureMetadataType.POWERAUTH)
})
public interface SignatureMetadata<String, Object> extends Serializable {

}


