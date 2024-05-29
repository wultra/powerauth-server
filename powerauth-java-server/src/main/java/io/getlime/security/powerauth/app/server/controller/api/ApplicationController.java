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

import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.request.LookupApplicationByAppKeyRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationListResponse;
import com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to applications.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("applicationController")
@RequestMapping("/rest/v3/application")
@Tag(name = "PowerAuth Application Controller (V3)")
@Slf4j
public class ApplicationController {

    private final ApplicationServiceBehavior applicationService;

    @Autowired
    public ApplicationController( ApplicationServiceBehavior applicationService) {
        this.applicationService = applicationService;
    }

    /**
     * Get the list of applications.
     *
     * @return Application list response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<GetApplicationListResponse> getApplicationList() throws Exception {
        logger.info("GetApplicationListRequest received");
        final ObjectResponse<GetApplicationListResponse> response = new ObjectResponse<>("OK", applicationService.getApplicationList());
        logger.info("GetApplicationListRequest succeeded: {}", response);
        return response;
    }

    /**
     * Create a new application.
     *
     * @param request Create application request.
     * @return Create application response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateApplicationResponse> createApplication(@RequestBody ObjectRequest<CreateApplicationRequest> request) throws Exception {
        logger.info("CreateApplicationRequest received: {}", request);
        final ObjectResponse<CreateApplicationResponse> response = new ObjectResponse<>("OK", applicationService.createApplication(request.getRequestObject()));
        logger.info("CreateApplicationRequest succeeded: {}", response);
        return response;
    }

    /**
     * Fetch application detail.
     *
     * @param request Application detail request.
     * @return Application detail response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/detail")
    public ObjectResponse<GetApplicationDetailResponse> getApplicationDetail(@RequestBody ObjectRequest<GetApplicationDetailRequest> request) throws Exception {
        logger.info("GetApplicationDetailRequest received: {}", request);
        final ObjectResponse<GetApplicationDetailResponse> response = new ObjectResponse<>("OK", applicationService.getApplicationDetail(request.getRequestObject()));
        logger.info("GetApplicationDetailRequest succeeded: {}", response);
        return response;
    }

    /**
     * Lookup application by app key.
     *
     * @param request Application detail request.
     * @return Application detail response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/detail/version")
    public ObjectResponse<LookupApplicationByAppKeyResponse> lookupApplicationByAppKey(@RequestBody ObjectRequest<LookupApplicationByAppKeyRequest> request) throws Exception {
        logger.info("LookupApplicationByAppKeyRequest received: {}", request);
        final ObjectResponse<LookupApplicationByAppKeyResponse> response = new ObjectResponse<>("OK", applicationService.lookupApplicationByAppKey(request.getRequestObject()));
        logger.info("LookupApplicationByAppKeyRequest succeeded: {}", response);
        return response;
    }

}
