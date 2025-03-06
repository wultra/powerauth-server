/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.database.repository.TemporaryKeyRepository;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.client.model.request.RemoveTemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.RemoveTemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

/**
 * Behavior class implementing the temporary key request related processes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class TemporaryKeyBehavior {

    private final TemporaryKeyRepository temporaryKeyRepository;
    private final CryptographyServiceFactory cryptographyServiceFactory;

    @Transactional
    public TemporaryPublicKeyResponse requestTemporaryKey(TemporaryPublicKeyRequest request) throws GenericServiceException {
        final String jwt = request.getJwt();
        final String signedJwt = cryptographyServiceFactory.getService(null).requestTemporaryKey(jwt);

        final TemporaryPublicKeyResponse response = new TemporaryPublicKeyResponse();
        response.setJwt(signedJwt);
        return response;
    }

    @Transactional
    public RemoveTemporaryPublicKeyResponse removeTemporaryKey(RemoveTemporaryPublicKeyRequest requestObject) {
        temporaryKeyRepository.deleteById(requestObject.getId());
        final RemoveTemporaryPublicKeyResponse response = new RemoveTemporaryPublicKeyResponse();
        response.setRemoved(true);
        response.setId(requestObject.getId());
        return response;
    }

    // Tasks for scheduling
    @Transactional
    public void expireTemporaryKeys() {
        final Date currentTimestamp = new Date();
        final int expiredCount = temporaryKeyRepository.deleteExpiredKeys(currentTimestamp);
        logger.debug("Removed {} expired temporary keys", expiredCount);
    }

}
