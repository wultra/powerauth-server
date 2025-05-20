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
 *
 */

package io.getlime.security.powerauth.app.server.service.replay;

import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;

import java.util.Date;

public interface ReplayVerificationService {

    /**
     * Check whether unique cryptography value exists and persist this value.
     * @param type Unique value type.
     * @param requestTimestamp Request timestamp.
     * @param ephemeralPublicKey Ephemeral public key bytes encoded in Base64.
     * @param nonce Nonce bytes encoded in Base64.
     * @param identifier Identifier for the record.
     * @param version Protocol version.
     * @throws GenericServiceException Thrown in case unique value exists.
     */
    void checkAndPersistUniqueValue(UniqueValueType type, Date requestTimestamp, String ephemeralPublicKey, String nonce, String identifier, String version) throws GenericServiceException;

}
