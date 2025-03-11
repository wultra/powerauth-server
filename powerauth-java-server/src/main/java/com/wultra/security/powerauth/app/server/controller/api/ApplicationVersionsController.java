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

import com.wultra.security.powerauth.client.model.request.CreateApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.SupportApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.UnsupportApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse;
import com.wultra.security.powerauth.client.model.response.SupportApplicationVersionResponse;
import com.wultra.security.powerauth.client.model.response.UnsupportApplicationVersionResponse;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
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
 * Controller managing the endpoints related to application versions.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("applicationVersionsController")
@RequestMapping({"/rest/v3/application/version", "/rest/v4/application/version"})
@Tag(name = "PowerAuth Application Version Controller")
@Validated
@Slf4j
public class ApplicationVersionsController {

    private final ApplicationServiceBehavior applicationServiceBehavior;

    @Autowired
    public ApplicationVersionsController(ApplicationServiceBehavior applicationServiceBehavior) {
        this.applicationServiceBehavior = applicationServiceBehavior;
    }

    /**
     * Create application version.
     *
     * @param request Create application version request.
     * @return Create application version response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateApplicationVersionResponse> createApplicationVersion(@Valid @RequestBody ObjectRequest<CreateApplicationVersionRequest> request) throws Exception {
        final CreateApplicationVersionRequest req = request.getRequestObject();
        logger.info("action: createApplicationVersion, state: initiated, applicationId: {}, versionId: {}", req.getApplicationId(), req.getApplicationVersionId());
        logger.debug("action: createApplicationVersion, state: initiated, request: {}", request);
        final CreateApplicationVersionResponse response = applicationServiceBehavior.createApplicationVersion(req);
        logger.info("action: createApplicationVersion, state: succeeded");
        logger.debug("action: createApplicationVersion, state: succeeded, response: {}", response);
        return new ObjectResponse<>(response);
    }

    /**
     * Unsupport application version.
     *
     * @param request Unsupport application version request.
     * @return Unsupport application version response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/unsupport")
    public ObjectResponse<UnsupportApplicationVersionResponse> unsupportApplicationVersion(@Valid @RequestBody ObjectRequest<UnsupportApplicationVersionRequest> request) throws Exception {
        final UnsupportApplicationVersionRequest req = request.getRequestObject();
        logger.info("action: unsupportApplicationVersion, state: initiated, applicationId: {}, versionId: {}", req.getApplicationId(), req.getApplicationVersionId());
        logger.debug("action: unsupportApplicationVersion, state: initiated, request: {}", request);
        final UnsupportApplicationVersionResponse response = applicationServiceBehavior.unsupportApplicationVersion(req);
        logger.info("action: unsupportApplicationVersion, state: succeeded");
        logger.debug("action: unsupportApplicationVersion, state: succeeded, response: {}", response);
        return new ObjectResponse<>(response);
    }

    /**
     * Support application version.
     *
     * @param request Support application version request.
     * @return Support application version response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/support")
    public ObjectResponse<SupportApplicationVersionResponse> supportApplicationVersion(@Valid @RequestBody ObjectRequest<SupportApplicationVersionRequest> request) throws Exception {
        final SupportApplicationVersionRequest req = request.getRequestObject();
        logger.info("action: supportApplicationVersion, state: initiated, applicationId: {}, versionId: {}", req.getApplicationId(), req.getApplicationVersionId());
        logger.debug("action: supportApplicationVersion, state: initiated, request: {}", request);
        final SupportApplicationVersionResponse response = applicationServiceBehavior.supportApplicationVersion(req);
        logger.info("action: supportApplicationVersion, state: succeeded");
        logger.debug("action: supportApplicationVersion, state: succeeded, response: {}", response);
        return new ObjectResponse<>(response);
    }

}
