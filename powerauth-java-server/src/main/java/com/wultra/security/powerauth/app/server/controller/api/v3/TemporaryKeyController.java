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
 */

package com.wultra.security.powerauth.app.server.controller.api.v3;

import com.wultra.security.powerauth.client.model.request.RemoveTemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.RemoveTemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.TemporaryKeyBehaviorEcies;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to temporary keys.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("temporaryKeyControllerV3")
@RequestMapping("/rest/v3/keystore")
@Tag(name = "PowerAuth Temporary Key Controller (V3)")
@AllArgsConstructor
@Validated
@Slf4j
public class TemporaryKeyController {

    private final TemporaryKeyBehaviorEcies service;

    /**
     * Create temporary key.
     *
     * @param request Get temporary key parameters for given request.
     * @return Response with temporary key.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<TemporaryPublicKeyResponse> createTemporaryKey(@Valid @RequestBody ObjectRequest<TemporaryPublicKeyRequest> request) throws Exception {
        final TemporaryPublicKeyRequest req = request.getRequestObject();
        logger.info("action: createTemporaryKey, state: initiated");
        logger.debug("action: createTemporaryKey, state: initiated, request: {}", request);
        final ObjectResponse<TemporaryPublicKeyResponse> response = new ObjectResponse<>(service.requestTemporaryKey(req));
        logger.info("action: createTemporaryKey, state: succeeded");
        logger.debug("action: createTemporaryKey, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Delete temporary key.
     *
     * @param request Delete temporary key with given ID.
     * @return Response with deletion result.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveTemporaryPublicKeyResponse> deleteTemporaryKey(@Valid @RequestBody ObjectRequest<RemoveTemporaryPublicKeyRequest> request) {
        final RemoveTemporaryPublicKeyRequest req = request.getRequestObject();
        logger.info("action: deleteTemporaryKey, state: initiated, temporaryKeyId: {}", req.getId());
        logger.debug("action: deleteTemporaryKey, state: initiated, request: {}", request);
        final ObjectResponse<RemoveTemporaryPublicKeyResponse> response = new ObjectResponse<>(service.removeTemporaryKey(req));
        logger.info("action: deleteTemporaryKey, state: succeeded");
        logger.debug("action: deleteTemporaryKey, state: succeeded, response: {}", response);
        return response;
    }

}
