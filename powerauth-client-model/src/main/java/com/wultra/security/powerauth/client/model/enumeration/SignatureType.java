/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

package com.wultra.security.powerauth.client.model.enumeration;

/**
 * Response enum for PowerAuth Signature Types.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public enum SignatureType {

    /**
     * 1FA signature using possession factor key, value = "possession"
     */
    POSSESSION,

    /**
     * 1FA signature using knowledge factor key, value = "knowledge"
     */
    KNOWLEDGE,

    /**
     * 1FA signature using biometry factor key, value = "biometry"
     */
    BIOMETRY,

    /**
     * 2FA signature using possession and knowledge factor key, value = "possession_knowledge"
     */
    POSSESSION_KNOWLEDGE,

    /**
     * 2FA signature using possession and biometry factor key, value = "possession_biometry"
     */
    POSSESSION_BIOMETRY,

    /**
     * 3FA signature using possession, knowledge and biometry factor key, value = "possession_knowledge_biometry"
     */
    POSSESSION_KNOWLEDGE_BIOMETRY;

    /**
     * Get enum value from provided string. In case the provided value does not match any value, null value is returned.
     * @param value String to get the enum value for.
     * @return Enum value.
     */
    public static SignatureType enumFromString(String value) {
        if (value == null) {
            return null;
        }
        try {
            // Try performing the fetch from fast enum map as is, which should work in most cases since
            // services are called via technical interfaces.
            return SignatureType.valueOf(value);
        } catch (IllegalArgumentException ex) {
            try {
                // Attempt to match the enum name as an upper case, as a fallback
                return SignatureType.valueOf(value.toUpperCase());
            } catch (IllegalArgumentException ex2) {
                // Unable to fetch the enum name
                return null;
            }
        }
    }

}
