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

package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;

/**
 * Service for handling encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface EncryptionService {

    /**
     * Decrypt an encrypted request.
     * @param encryptedRequest Encrypted request.
     * @param protocolVersion Cryptography protocol version.
     * @param applicationKey Application key.
     * @param activationId Activation ID.
     * @param encryptorId Encryptor ID.
     * @param validateRequest Whether request should be validated.
     * @return Decryption result.
     * @throws GenericServiceException In case of a cryptography error.
     */
    DecryptionResult decrypt(EncryptedRequest encryptedRequest, String protocolVersion, String applicationKey, String activationId, EncryptorId encryptorId, boolean validateRequest) throws GenericServiceException;

}
