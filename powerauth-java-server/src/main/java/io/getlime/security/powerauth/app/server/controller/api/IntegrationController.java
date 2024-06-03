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

import com.wultra.security.powerauth.client.model.request.CreateIntegrationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveIntegrationRequest;
import com.wultra.security.powerauth.client.model.response.CreateIntegrationResponse;
import com.wultra.security.powerauth.client.model.response.GetIntegrationListResponse;
import com.wultra.security.powerauth.client.model.response.RemoveIntegrationResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.IntegrationBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to integrated applications.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("integrationController")
@RequestMapping("/rest/v3/integration")
@Tag(name = "PowerAuth Integration Controller (V3)")
@Slf4j
public class IntegrationController {

    private final IntegrationBehavior service;

    @Autowired
    public IntegrationController(IntegrationBehavior service) {
        this.service = service;
    }

    /**
     * Create integration request.
     *
     * @param request Create integration request.
     * @return Create integration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateIntegrationResponse> createIntegration(@RequestBody ObjectRequest<CreateIntegrationRequest> request) throws Exception {
        logger.info("CreateIntegrationRequest received: {}", request);
        final ObjectResponse<CreateIntegrationResponse> response = new ObjectResponse<>(service.createIntegration(request.getRequestObject()));
        logger.info("CreateIntegrationRequest succeeded: {}", response);
        return response;
    }

    /**
     * Get integration list.
     *
     * @return Get integration list response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<GetIntegrationListResponse> getIntegrationList() throws Exception {
        logger.info("GetIntegrationListRequest received");
        final ObjectResponse<GetIntegrationListResponse> response = new ObjectResponse<>(service.getIntegrationList());
        logger.info("GetIntegrationListRequest succeeded: {}", response);
        return response;
    }

    /**
     * Remove integration.
     *
     * @param request Remove integration request.
     * @return Remove integration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveIntegrationResponse> removeIntegration(@RequestBody ObjectRequest<RemoveIntegrationRequest> request) throws Exception {
        logger.info("RemoveIntegrationRequest received: {}", request);
        final ObjectResponse<RemoveIntegrationResponse> response = new ObjectResponse<>(service.removeIntegration(request.getRequestObject()));
        logger.info("RemoveIntegrationRequest succeeded: {}", response);
        return response;
    }

}
