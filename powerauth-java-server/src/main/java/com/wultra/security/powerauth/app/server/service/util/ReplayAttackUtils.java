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

package com.wultra.security.powerauth.app.server.service.util;

import com.wultra.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import com.wultra.security.powerauth.app.server.service.model.UniqueValueParam;

/**
 * Utilities for deriving unique value parameters in encrypted requests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ReplayAttackUtils {

    /**
     * Derive unique value parameters based on protocol version for application scope.
     *
     * @param protocolVersion Protocol version.
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param nonce Nonce.
     * @param temporaryKeyId Temporary key ID.
     *
     * @return Unique value parameters.
     */
    public static UniqueValueParam deriveUniqueValuesApplicationScope(String protocolVersion, String applicationKey, String ephemeralPublicKey, String nonce, String temporaryKeyId) {
        final UniqueValueParam param = new UniqueValueParam();
        param.setEphemeralPublicKey(ephemeralPublicKey);
        param.setNonce(nonce);
        if (protocolVersion.equals("3.0") || protocolVersion.equals("3.1") || protocolVersion.equals("3.2")) {
            param.setApplicationKey(applicationKey);
            param.setIdentifier(null);
            param.setUniqueValueType(UniqueValueType.ECIES_APPLICATION_SCOPE);
        } else if (protocolVersion.equals("3.3")) {
            param.setApplicationKey(null);
            param.setIdentifier(temporaryKeyId);
            param.setUniqueValueType(UniqueValueType.ECIES_WITH_TEMPORARY_KEY);
        } else {
            param.setApplicationKey(null);
            param.setIdentifier(temporaryKeyId);
            param.setUniqueValueType(UniqueValueType.AEAD_V4);
        }
        return param;
    }

    /**
     * Derive unique value parameters based on protocol version for activation scope.
     *
     * @param protocolVersion Protocol version.
     * @param applicationKey Application key.
     * @param temporaryKeyId Temporary key ID.
     *
     * @return Unique value parameters.
     */
    public static UniqueValueParam deriveUniqueValuesActivationScope(String protocolVersion, String applicationKey, String ephemeralPublicKey, String nonce, String temporaryKeyId, String activationId) {
        final UniqueValueParam param = new UniqueValueParam();
        param.setEphemeralPublicKey(ephemeralPublicKey);
        param.setNonce(nonce);
        if (protocolVersion.equals("3.0") || protocolVersion.equals("3.1") || protocolVersion.equals("3.2")) {
            param.setApplicationKey(applicationKey);
            param.setIdentifier(activationId);
            param.setUniqueValueType(UniqueValueType.ECIES_ACTIVATION_SCOPE);
        } else if (protocolVersion.equals("3.3")) {
            param.setApplicationKey(null);
            param.setIdentifier(temporaryKeyId);
            param.setUniqueValueType(UniqueValueType.ECIES_WITH_TEMPORARY_KEY);
        } else {
            param.setApplicationKey(null);
            param.setIdentifier(temporaryKeyId);
            param.setUniqueValueType(UniqueValueType.AEAD_V4);
        }
        return param;
    }

}
