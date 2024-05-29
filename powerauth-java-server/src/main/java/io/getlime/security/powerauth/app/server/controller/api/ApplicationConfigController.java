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

import com.wultra.security.powerauth.client.model.request.CreateApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to application config.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("applicationConfigController")
@RequestMapping("/rest/v3/application/config")
@Tag(name = "PowerAuth Application Config Controller (V3)")
@Slf4j
public class ApplicationConfigController {

    private final ApplicationConfigServiceBehavior service;

    @Autowired
    public ApplicationConfigController(ApplicationConfigServiceBehavior service) {
        this.service = service;
    }

    /**
     * Get application config.
     *
     * @param request Get application configuration.
     * @return Application configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/config/detail")
    public ObjectResponse<GetApplicationConfigResponse> getApplicationConfig(@RequestBody ObjectRequest<GetApplicationConfigRequest> request) throws Exception {
        logger.info("GetApplicationConfig call received: {}", request);
        final ObjectResponse<GetApplicationConfigResponse> response = new ObjectResponse<>(service.getApplicationConfig(request.getRequestObject()));
        logger.info("GetApplicationConfig succeeded: {}", response);
        return response;
    }

    /**
     * Create application config.
     *
     * @param request Create an application configuration.
     * @return Create application configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/config/create")
    public ObjectResponse<CreateApplicationConfigResponse> createApplicationConfig(@RequestBody ObjectRequest<CreateApplicationConfigRequest> request) throws Exception {
        logger.info("CreateApplicationConfig call received: {}", request);
        final ObjectResponse<CreateApplicationConfigResponse> response = new ObjectResponse<>(service.createApplicationConfig(request.getRequestObject()));
        logger.info("CreateApplicationConfig succeeded: {}", response);
        return response;
    }

    /**
     * Remove application config.
     *
     * @param request Delete an application configuration.
     * @return Delete application configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/config/remove")
    public Response removeApplicationConfig(@RequestBody ObjectRequest<RemoveApplicationConfigRequest> request) throws Exception {
        logger.info("RemoveApplicationConfig call received: {}", request);
        service.removeApplicationConfig(request.getRequestObject());
        logger.info("RemoveApplicationConfig succeeded.");
        return new Response();
    }

}
