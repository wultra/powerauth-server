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

import com.wultra.security.powerauth.client.model.request.ActivationHistoryRequest;
import com.wultra.security.powerauth.client.model.response.ActivationHistoryResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to activations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("activationHistoryController")
@RequestMapping("/rest/v3/activation/history")
@Tag(name = "PowerAuth Activation History Controller (V3)")
@Slf4j
public class ActivationHistoryController {

    private final ActivationHistoryServiceBehavior service;

    @Autowired
    public ActivationHistoryController(ActivationHistoryServiceBehavior service) {
        this.service = service;
    }

    /**
     * Obtain the activation history.
     *
     * @param request Activation history request.
     * @return Activation history response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping
    public ObjectResponse<ActivationHistoryResponse> getActivationHistory(@RequestBody ObjectRequest<ActivationHistoryRequest> request) throws Exception {
        logger.info("ActivationHistoryRequest received: {}", request);
        final ObjectResponse<ActivationHistoryResponse> response = new ObjectResponse<>("OK", service.getActivationHistory(request.getRequestObject()));
        logger.info("ActivationHistoryRequest succeeded: {}", response);
        return response;
    }


}
