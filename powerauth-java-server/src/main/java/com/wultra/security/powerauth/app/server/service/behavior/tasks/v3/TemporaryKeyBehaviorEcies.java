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

package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.app.server.service.crypto.v3.TemporaryKeyServiceEcies;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.persistence.TemporaryKeyPersistenceService;
import com.wultra.security.powerauth.client.model.request.RemoveTemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.RemoveTemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Behavior class implementing the temporary key request related processes using ECIES encryption.
 *
 * @author Roman Strobl, roman.strob@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class TemporaryKeyBehaviorEcies {

    private final TemporaryKeyPersistenceService temporaryKeyPersistenceService;
    private final TemporaryKeyServiceEcies temporaryKeyServiceEcies;

    @Transactional
    public TemporaryPublicKeyResponse requestTemporaryKey(TemporaryPublicKeyRequest request) throws GenericServiceException {
            final String jwt = request.getJwt();
            final String signedJwt = temporaryKeyServiceEcies.requestTemporaryKey(jwt);
            final TemporaryPublicKeyResponse response = new TemporaryPublicKeyResponse();
            response.setJwt(signedJwt);
            return response;
    }

    @Transactional
    public RemoveTemporaryPublicKeyResponse removeTemporaryKey(RemoveTemporaryPublicKeyRequest requestObject) {
        temporaryKeyPersistenceService.removeTemporaryKey(requestObject.getId());
        final RemoveTemporaryPublicKeyResponse response = new RemoveTemporaryPublicKeyResponse();
        response.setRemoved(true);
        response.setId(requestObject.getId());
        return response;
    }

}
