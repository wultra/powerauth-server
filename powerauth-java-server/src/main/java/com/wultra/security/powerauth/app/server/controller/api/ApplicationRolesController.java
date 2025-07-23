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

package com.wultra.security.powerauth.app.server.controller.api;

import com.wultra.security.powerauth.client.model.request.AddApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.ListApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.UpdateApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationRolesServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
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
@RequestMapping({"/rest/v3/application/roles", "/rest/v4/application/roles"})
@Tag(name = "PowerAuth Application Roles Controller")
@AllArgsConstructor
@Validated
@Slf4j
public class ApplicationRolesController {

    private final ApplicationRolesServiceBehavior service;

    /**
     * List application roles.
     *
     * @param request List application roles request.
     * @return List application roles response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<ListApplicationRolesResponse> listApplicationRoles(@Valid @RequestBody ObjectRequest<ListApplicationRolesRequest> request) throws Exception {
        final ListApplicationRolesRequest req = request.getRequestObject();
        logger.info("action: listApplicationRoles, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: listApplicationRoles, state: initiated, request: {}", request);
        final ObjectResponse<ListApplicationRolesResponse> response = new ObjectResponse<>(service.listApplicationRoles(req));
        logger.info("action: listApplicationRoles, state: succeeded");
        logger.debug("action: listApplicationRoles, state: succeeded, response: {}", response);
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
    public ObjectResponse<AddApplicationRolesResponse> addApplicationRoles(@Valid @RequestBody ObjectRequest<AddApplicationRolesRequest> request) throws Exception {
        final AddApplicationRolesRequest req = request.getRequestObject();
        logger.info("action: addApplicationRoles, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: addApplicationRoles, state: initiated, request: {}", request);
        final ObjectResponse<AddApplicationRolesResponse> response = new ObjectResponse<>(service.addApplicationRoles(req));
        logger.info("action: addApplicationRoles, state: succeeded");
        logger.debug("action: addApplicationRoles, state: succeeded, response: {}", response);
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
    public ObjectResponse<UpdateApplicationRolesResponse> updateApplicationRoles(@Valid @RequestBody ObjectRequest<UpdateApplicationRolesRequest> request) throws Exception {
        final UpdateApplicationRolesRequest req = request.getRequestObject();
        logger.info("action: updateApplicationRoles, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: updateApplicationRoles, state: initiated, request: {}", request);
        final ObjectResponse<UpdateApplicationRolesResponse> response = new ObjectResponse<>(service.updateApplicationRoles(req));
        logger.info("action: updateApplicationRoles, state: succeeded");
        logger.debug("action: updateApplicationRoles, state: succeeded, response: {}", response);
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
    public ObjectResponse<RemoveApplicationRolesResponse> removeApplicationRoles(@Valid @RequestBody ObjectRequest<RemoveApplicationRolesRequest> request) throws Exception {
        final RemoveApplicationRolesRequest req = request.getRequestObject();
        logger.info("action: removeApplicationRoles, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: removeApplicationRoles, state: initiated, request: {}", request);
        final ObjectResponse<RemoveApplicationRolesResponse> response = new ObjectResponse<>(service.removeApplicationRoles(req));
        logger.info("action: removeApplicationRoles, state: succeeded");
        logger.debug("action: removeApplicationRoles, state: succeeded, response: {}", response);
        return response;
    }

}
