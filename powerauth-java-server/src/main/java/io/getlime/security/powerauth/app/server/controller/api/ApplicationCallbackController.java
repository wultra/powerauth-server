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

import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
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
 * Controller managing the endpoints related to application callbacks.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("applicationCallbackController")
@RequestMapping("/rest/v3/application/callback")
@Tag(name = "PowerAuth Application Callback Controller (V3)")
@Validated
@Slf4j
public class ApplicationCallbackController {

    private final CallbackUrlBehavior service;

    @Autowired
    public ApplicationCallbackController(CallbackUrlBehavior service) {
        this.service = service;
    }

    /**
     * Create a new callback.
     *
     * @param request Create callback URL request.
     * @return Create callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateCallbackUrlResponse> createCallbackUrl(@Valid @RequestBody ObjectRequest<CreateCallbackUrlRequest> request) throws Exception {
        final CreateCallbackUrlRequest req = request.getRequestObject();
        logger.info("action: createCallbackUrl, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: createCallbackUrl, state: initiated, request: {}", request);
        final ObjectResponse<CreateCallbackUrlResponse> response = new ObjectResponse<>(service.createCallbackUrl(req));
        logger.info("action: createCallbackUrl, state: succeeded");
        logger.debug("action: createCallbackUrl, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Update callback.
     *
     * @param request Update callback URL request.
     * @return Update callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/update")
    public ObjectResponse<UpdateCallbackUrlResponse> updateCallbackUrl(@Valid @RequestBody ObjectRequest<UpdateCallbackUrlRequest> request) throws Exception {
        final UpdateCallbackUrlRequest req = request.getRequestObject();
        logger.info("action: updateCallbackUrl, state: initiated, callbackId: {}", req.getId());
        logger.debug("action: updateCallbackUrl, state: initiated, request: {}", request);
        final ObjectResponse<UpdateCallbackUrlResponse> response = new ObjectResponse<>(service.updateCallbackUrl(req));
        logger.info("action: updateCallbackUrl, state: succeeded");
        logger.debug("action: updateCallbackUrl, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Get callback list.
     *
     * @param request Get callback URL list request.
     * @return Get callback URL list response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<GetCallbackUrlListResponse> getCallbackUrlList(@Valid @RequestBody ObjectRequest<GetCallbackUrlListRequest> request) throws Exception {
        final GetCallbackUrlListRequest req = request.getRequestObject();
        logger.info("action: getCallbackUrlList, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: getCallbackUrlList, state: initiated, request: {}", request);
        final ObjectResponse<GetCallbackUrlListResponse> response = new ObjectResponse<>(service.getCallbackUrlList(req));
        logger.info("action: getCallbackUrlList, state: succeeded");
        logger.debug("action: getCallbackUrlList, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Remove callback.
     *
     * @param request Remove callback URL request.
     * @return Remove callback URL response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveCallbackUrlResponse> removeCallbackUrl(@Valid @RequestBody ObjectRequest<RemoveCallbackUrlRequest> request) throws Exception {
        final RemoveCallbackUrlRequest req = request.getRequestObject();
        logger.info("action: removeCallbackUrl, state: initiated, callbackId: {}", req.getId());
        logger.debug("action: removeCallbackUrl, state: initiated, request: {}", request);
        final ObjectResponse<RemoveCallbackUrlResponse> response = new ObjectResponse<>(service.removeCallbackUrl(req));
        logger.info("action: removeCallbackUrl, state: succeeded");
        logger.debug("action: removeCallbackUrl, state: succeeded, response: {}", response);
        return response;
    }

}
