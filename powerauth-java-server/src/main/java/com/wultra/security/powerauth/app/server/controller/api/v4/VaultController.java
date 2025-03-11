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

package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.VaultUnlockServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to secure vault.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("vaultControllerV4")
@RequestMapping("/rest/v4/vault")
@Tag(name = "PowerAuth Vault Controller (V4)")
@Validated
@Slf4j
public class VaultController {

    private final VaultUnlockServiceBehavior service;

    @Autowired
    public VaultController(VaultUnlockServiceBehavior service) {
        this.service = service;
    }

    /**
     * Unlock vault.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/unlock")
    public ObjectResponse<com.wultra.security.powerauth.client.model.response.v4.VaultUnlockResponse> unlockVault(@Valid @RequestBody ObjectRequest<com.wultra.security.powerauth.client.model.request.v4.VaultUnlockRequest> request) throws Exception {
        final com.wultra.security.powerauth.client.model.request.v4.VaultUnlockRequest req = request.getRequestObject();
        logger.info("action: unlockVault, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: unlockVault, state: initiated, request: {}", request);
        final ObjectResponse<com.wultra.security.powerauth.client.model.response.v4.VaultUnlockResponse> response = new ObjectResponse<>(service.unlockVault(req));
        logger.info("action: unlockVault, state: succeeded");
        logger.debug("action: unlockVault, state: succeeded, response: {}", response);
        return response;
    }

}
