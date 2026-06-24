/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.ConfigStoreServiceBehavior;
import com.wultra.security.powerauth.client.model.request.v4.CreateConfigItemRequest;
import com.wultra.security.powerauth.client.model.request.v4.FetchConfigRequest;
import com.wultra.security.powerauth.client.model.request.v4.GetConfigItemsRequest;
import com.wultra.security.powerauth.client.model.request.v4.RemoveConfigItemRequest;
import com.wultra.security.powerauth.client.model.response.v4.CreateConfigItemResponse;
import com.wultra.security.powerauth.client.model.response.v4.FetchConfigResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetConfigItemsResponse;
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
 * Controller managing the endpoints of the secure configuration store (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("configStoreControllerV4")
@RequestMapping("/rest/v4/config-store")
@Tag(name = "PowerAuth Config Store Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class ConfigStoreController {

    private final ConfigStoreServiceBehavior service;

    /**
     * Create or update a single configuration item.
     *
     * @param request Create configuration item request.
     * @return Create configuration item response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateConfigItemResponse> createConfigItem(@Valid @RequestBody ObjectRequest<CreateConfigItemRequest> request) throws Exception {
        final CreateConfigItemRequest req = request.getRequestObject();
        logger.info("action: createConfigItem, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: createConfigItem, state: initiated, request: {}", request);
        final ObjectResponse<CreateConfigItemResponse> response = new ObjectResponse<>(service.createConfigItem(req));
        logger.info("action: createConfigItem, state: succeeded");
        logger.debug("action: createConfigItem, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * List configuration items.
     *
     * @param request List configuration items request.
     * @return List configuration items response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<GetConfigItemsResponse> listConfigItems(@Valid @RequestBody ObjectRequest<GetConfigItemsRequest> request) throws Exception {
        final GetConfigItemsRequest req = request.getRequestObject();
        logger.info("action: listConfigItems, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: listConfigItems, state: initiated, request: {}", request);
        final ObjectResponse<GetConfigItemsResponse> response = new ObjectResponse<>(service.getConfigItems(req));
        logger.info("action: listConfigItems, state: succeeded");
        logger.debug("action: listConfigItems, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Remove a single configuration item.
     *
     * @param request Remove configuration item request.
     * @return Simple response object.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public Response removeConfigItem(@Valid @RequestBody ObjectRequest<RemoveConfigItemRequest> request) throws Exception {
        final RemoveConfigItemRequest req = request.getRequestObject();
        logger.info("action: removeConfigItem, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: removeConfigItem, state: initiated, request: {}", request);
        service.removeConfigItem(req);
        final Response response = new Response();
        logger.info("action: removeConfigItem, state: succeeded");
        logger.debug("action: removeConfigItem, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Fetch the configuration items visible to a mobile SDK caller (server-to-server read API).
     * <p>
     * This endpoint is consumed by the restful-integration, which terminates the end-to-end encryption tunnel.
     *
     * @param request Fetch configuration request.
     * @return Fetch configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/fetch")
    public ObjectResponse<FetchConfigResponse> fetchConfigItems(@Valid @RequestBody ObjectRequest<FetchConfigRequest> request) throws Exception {
        final FetchConfigRequest req = request.getRequestObject();
        logger.info("action: fetchConfigItems, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: fetchConfigItems, state: initiated, request: {}", request);
        final ObjectResponse<FetchConfigResponse> response = new ObjectResponse<>(service.fetchConfig(req));
        logger.info("action: fetchConfigItems, state: succeeded");
        logger.debug("action: fetchConfigItems, state: succeeded, response: {}", response);
        return response;
    }

}
