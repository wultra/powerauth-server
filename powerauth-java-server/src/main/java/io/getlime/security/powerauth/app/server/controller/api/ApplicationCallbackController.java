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

import com.wultra.security.powerauth.client.model.request.CreateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.GetCallbackUrlListRequest;
import com.wultra.security.powerauth.client.model.request.RemoveCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.UpdateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
    public ObjectResponse<CreateCallbackUrlResponse> createCallbackUrl(@RequestBody ObjectRequest<CreateCallbackUrlRequest> request) throws Exception {
        logger.info("CreateCallbackUrlRequest received: {}", request);
        final ObjectResponse<CreateCallbackUrlResponse> response = new ObjectResponse<>("OK", service.createCallbackUrl(request.getRequestObject()));
        logger.info("CreateCallbackUrlRequest succeeded: {}", response);
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
    public ObjectResponse<UpdateCallbackUrlResponse> updateCallbackUrl(@RequestBody ObjectRequest<UpdateCallbackUrlRequest> request) throws Exception {
        logger.info("UpdateCallbackUrlRequest received: {}", request);
        final ObjectResponse<UpdateCallbackUrlResponse> response = new ObjectResponse<>("OK", service.updateCallbackUrl(request.getRequestObject()));
        logger.info("UpdateCallbackUrlRequest succeeded: {}", response);
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
    public ObjectResponse<GetCallbackUrlListResponse> getCallbackUrlList(@RequestBody ObjectRequest<GetCallbackUrlListRequest> request) throws Exception {
        logger.info("GetCallbackUrlListRequest received: {}", request);
        final ObjectResponse<GetCallbackUrlListResponse> response = new ObjectResponse<>("OK", service.getCallbackUrlList(request.getRequestObject()));
        logger.info("GetCallbackUrlListRequest succeeded: {}", response);
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
    public ObjectResponse<RemoveCallbackUrlResponse> removeCallbackUrl(@RequestBody ObjectRequest<RemoveCallbackUrlRequest> request) throws Exception {
        logger.info("RemoveCallbackUrlRequest received: {}", request);
        final ObjectResponse<RemoveCallbackUrlResponse> response = new ObjectResponse<>("OK", service.removeCallbackUrl(request.getRequestObject()));
        logger.info("RemoveCallbackUrlRequest succeeded: {}", response);
        return response;
    }

}
