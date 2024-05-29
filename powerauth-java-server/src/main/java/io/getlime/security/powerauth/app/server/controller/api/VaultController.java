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

import com.wultra.security.powerauth.client.model.request.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.response.VaultUnlockResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.VaultUnlockServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to secure vault.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("vaultController")
@RequestMapping("/rest/v3/vault")
@Tag(name = "PowerAuth Vault Controller (V3)")
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
    public ObjectResponse<VaultUnlockResponse> unlockVault(@RequestBody ObjectRequest<VaultUnlockRequest> request) throws Exception {
        logger.info("VaultUnlockRequest received: {}", request);
        final ObjectResponse<VaultUnlockResponse> response = new ObjectResponse<>("OK", service.unlockVault(request.getRequestObject()));
        logger.info("VaultUnlockRequest succeeded: {}", response);
        return response;
    }

}
