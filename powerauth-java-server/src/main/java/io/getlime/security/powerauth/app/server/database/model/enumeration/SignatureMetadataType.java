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

package io.getlime.security.powerauth.app.server.database.model.enumeration;

/**
 * Enumeration constants representing the types of signature metadata supported in the application.
 * These constants are used as names in JSON subtypes and therefore must be kept in sync.
 * <p>
 * Note: Although it is represented as a class with static final String fields, it serves
 * the purpose of an enum type for specific use cases that require constant String values.
 * </p>
 *
 * @author Jan Dusil
 */
public class SignatureMetadataType {

    /**
     * Represents PowerAuth signature metadata.
     * This value is used for identifying the type of metadata in JSON serialization/deserialization.
     */
    public static final String POWER_AUTH = "PowerAuthSignatureMetadata";
}

