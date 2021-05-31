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

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response enum for PowerAuth Signature Types.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public enum SignatureType {

    /**
     * 1FA signature using possession factor key, value = "possession"
     */
    POSSESSION("possession"),

    /**
     * 1FA signature using knowledge factor key, value = "knowledge"
     */
    KNOWLEDGE("knowledge"),

    /**
     * 1FA signature using biometry factor key, value = "biometry"
     */
    BIOMETRY("biometry"),

    /**
     * 2FA signature using possession and knowledge factor key, value = "possession_knowledge"
     */
    POSSESSION_KNOWLEDGE("possession_knowledge"),

    /**
     * 2FA signature using possession and biometry factor key, value = "possession_biometry"
     */
    POSSESSION_BIOMETRY("possession_biometry"),

    /**
     * 3FA signature using possession, knowledge and biometry factor key, value = "possession_knowledge_biometry"
     */
    POSSESSION_KNOWLEDGE_BIOMETRY("possession_knowledge_biometry");

    private final String value;

    SignatureType(final String value) {
        this.value = value;
    }

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
            // Make sure to match the enum name which is upper case, not 'value' that is lower case.
            return SignatureType.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    /**
     * Check if the enum value has the same name as a given string.
     * @param otherName Name to be checked.
     * @return True in case of enum value is equal to provided name.
     */
    public boolean equalsName(String otherName) {
        return value.equalsIgnoreCase(otherName);
    }

    @Override
    public String toString() {
        return this.value.toLowerCase();
    }

}
