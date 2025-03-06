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

import com.wultra.security.powerauth.app.server.service.crypto.v3.CryptographyServiceEc256;
import com.wultra.security.powerauth.app.server.service.crypto.v4.CryptographyServiceEc384;
import com.wultra.security.powerauth.app.server.service.crypto.v4.CryptographyServiceHybrid;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Factory for cryptography service.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@AllArgsConstructor
public class CryptographyServiceFactory {

    private final CryptographyServiceEc256 cryptographyServiceEc256;
    private final CryptographyServiceEc384 cryptographyServiceEc384;
    private final CryptographyServiceHybrid cryptographyServiceV4Hybrid;

    /**
     * Get cryptography service for given algorithm.
     * @param algorithm Algorithm to be used in cryptography.
     * @return Cryptography implementation.
     * @throws GenericServiceException Thrown in case of invalid request.
     */
    public CryptographyService getService(SharedSecretAlgorithm algorithm) throws GenericServiceException{
        if (algorithm == null) {
            return cryptographyServiceEc256;
        }
        return switch (algorithm) {
            case EC_P384 -> cryptographyServiceEc384;
            case EC_P384_ML_L3 -> cryptographyServiceV4Hybrid;
        };
    }
}
