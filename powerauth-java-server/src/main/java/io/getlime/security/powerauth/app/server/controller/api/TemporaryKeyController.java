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

package io.getlime.security.powerauth.app.server.controller.api;

import com.wultra.security.powerauth.client.model.request.RemoveTemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.RemoveTemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.TemporaryKeyBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to temporary keys.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("temporaryKeyController")
@RequestMapping("/rest/v3/keystore")
@Tag(name = "PowerAuth ECIES Temporary Key Controller (V3)")
@Slf4j
public class TemporaryKeyController {

    private final TemporaryKeyBehavior service;

    @Autowired
    public TemporaryKeyController(TemporaryKeyBehavior service) {
        this.service = service;
    }

    /**
     * Create temporary key.
     *
     * @param request Get temporary key parameters for given request.
     * @return Response with temporary key.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<TemporaryPublicKeyResponse> createTemporaryKey(@RequestBody ObjectRequest<TemporaryPublicKeyRequest> request) throws Exception {
        logger.info("TemporaryPublicKeyRequest received: {}", request);
        final ObjectResponse<TemporaryPublicKeyResponse> response = new ObjectResponse<>(service.requestTemporaryKey(request.getRequestObject()));
        logger.info("TemporaryPublicKeyRequest succeeded: {}", response);
        return response;
    }

    /**
     * Delete temporary key.
     *
     * @param request Delete temporary key with given ID.
     * @return Response with deletion result.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveTemporaryPublicKeyResponse> deleteTemporaryKey(@RequestBody ObjectRequest<RemoveTemporaryPublicKeyRequest> request) {
        logger.info("RemoveTemporaryPublicKeyRequest received: {}", request);
        final ObjectResponse<RemoveTemporaryPublicKeyResponse> response = new ObjectResponse<>(service.removeTemporaryKey(request.getRequestObject()));
        logger.info("RemoveTemporaryPublicKeyRequest succeeded: {}", response);
        return response;
    }

}
