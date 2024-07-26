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

import com.wultra.security.powerauth.client.model.request.AddApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.ListApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.UpdateApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ApplicationRolesServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to application roles.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("applicationRolesController")
@RequestMapping("/rest/v3/application/roles")
@Tag(name = "PowerAuth Application Roles Controller (V3)")
@Slf4j
public class ApplicationRolesController {

    private final ApplicationRolesServiceBehavior service;

    @Autowired
    public ApplicationRolesController(ApplicationRolesServiceBehavior service) {
        this.service = service;
    }

    /**
     * List application roles.
     *
     * @param request List application roles request.
     * @return List application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<ListApplicationRolesResponse> listApplicationRoles(@RequestBody ObjectRequest<ListApplicationRolesRequest> request) throws Exception {
        logger.info("ListApplicationRolesRequest received: {}", request);
        final ObjectResponse<ListApplicationRolesResponse> response = new ObjectResponse<>(service.listApplicationRoles(request.getRequestObject()));
        logger.info("ListApplicationRolesRequest succeeded: {}", response);
        return response;
    }

    /**
     * Create application roles.
     *
     * @param request Create application roles request.
     * @return Create application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<AddApplicationRolesResponse> addApplicationRoles(@RequestBody ObjectRequest<AddApplicationRolesRequest> request) throws Exception {
        logger.info("AddApplicationRolesRequest received: {}", request);
        final ObjectResponse<AddApplicationRolesResponse> response = new ObjectResponse<>(service.addApplicationRoles(request.getRequestObject()));
        logger.info("AddApplicationRolesRequest succeeded: {}", response);
        return response;
    }

    /**
     * Update application roles.
     *
     * @param request Update application roles request.
     * @return Update application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/update")
    public ObjectResponse<UpdateApplicationRolesResponse> updateApplicationRoles(@RequestBody ObjectRequest<UpdateApplicationRolesRequest> request) throws Exception {
        logger.info("UpdateApplicationRolesRequest received: {}", request);
        final ObjectResponse<UpdateApplicationRolesResponse> response = new ObjectResponse<>(service.updateApplicationRoles(request.getRequestObject()));
        logger.info("UpdateApplicationRolesRequest succeeded: {}", response);
        return response;
    }

    /**
     * Remove application roles.
     *
     * @param request Remove application roles request.
     * @return Remove application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveApplicationRolesResponse> removeApplicationRoles(@RequestBody ObjectRequest<RemoveApplicationRolesRequest> request) throws Exception {
        logger.info("RemoveApplicationRolesRequest received: {}", request);
        final ObjectResponse<RemoveApplicationRolesResponse> response = new ObjectResponse<>(service.removeApplicationRoles(request.getRequestObject()));
        logger.info("RemoveApplicationRolesRequest succeeded: {}", response);
        return response;
    }

}
