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

import java.security.PrivateKey;

/**
 * Service for handling temporary keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface TemporaryKeyService {

    /**
     * Request a temporary key.
     * @param jwt JWT temporary key request.
     * @return JWT temporary key response.
     * @throws GenericServiceException In case of cryptography error.
     */
    String requestTemporaryKey(String jwt) throws GenericServiceException;

    /**
     * Fetch a temporary private key for given ID and application key.
     * @param id Temporary key ID.
     * @param appKey Application key.
     * @return Temporary private key.
     * @throws GenericServiceException In case of cryptography error.
     */
    PrivateKey temporaryPrivateKey(String id, String appKey) throws GenericServiceException;

}
