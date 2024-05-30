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

import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDeleteRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDetailRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateUpdateRequest;
import com.wultra.security.powerauth.client.model.response.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationTemplateListResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OperationTemplateServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to operation templates.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("operationTemplatesController")
@RequestMapping("/rest/v3/operation/template")
@Tag(name = "PowerAuth Operation Templates Controller (V3)")
@Slf4j
public class OperationTemplatesController {

    private final OperationTemplateServiceBehavior service;

    @Autowired
    public OperationTemplatesController(OperationTemplateServiceBehavior service) {
        this.service = service;
    }

    /**
     * Get all operation templates.
     *
     * @return Get operation templates response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<OperationTemplateListResponse> getOperationTemplateList() throws Exception {
        logger.info("OperationTemplateListResponse call received");
        final ObjectResponse<OperationTemplateListResponse> response = new ObjectResponse<>(service.getAllTemplates());
        logger.info("OperationTemplateListResponse succeeded: {}", response);
        return response;
    }

    /**
     * Get operation template detail.
     *
     * @param request Get operation template detail request.
     * @return Get operation template detail response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/detail")
    public ObjectResponse<OperationTemplateDetailResponse> getOperationTemplateDetail(@RequestBody ObjectRequest<OperationTemplateDetailRequest> request) throws Exception {
        logger.info("OperationTemplateDetailRequest call received: {}", request);
        final ObjectResponse<OperationTemplateDetailResponse> response = new ObjectResponse<>(service.getTemplateDetail(request.getRequestObject()));
        logger.info("OperationTemplateDetailRequest succeeded: {}", response);
        return response;
    }

    /**
     * Create operation template.
     *
     * @param request Create operation template request.
     * @return Created operation template detail response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<OperationTemplateDetailResponse> createOperationTemplate(@RequestBody ObjectRequest<OperationTemplateCreateRequest> request) throws Exception {
        logger.info("OperationTemplateCreateRequest call received: {}", request);
        final ObjectResponse<OperationTemplateDetailResponse> response = new ObjectResponse<>(service.createOperationTemplate(request.getRequestObject()));
        logger.info("OperationTemplateCreateRequest succeeded: {}", response);
        return response;
    }

    /**
     * Update operation template.
     *
     * @param request Update operation template request.
     * @return Updated operation template detail response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/update")
    public ObjectResponse<OperationTemplateDetailResponse> updateOperationTemplate(@RequestBody ObjectRequest<OperationTemplateUpdateRequest> request) throws Exception {
        logger.info("OperationTemplateUpdateRequest call received: {}", request);
        final ObjectResponse<OperationTemplateDetailResponse> response = new ObjectResponse<>(service.updateOperationTemplate(request.getRequestObject()));
        logger.info("OperationTemplateUpdateRequest succeeded: {}", response);
        return response;
    }

    /**
     * Delete operation template.
     *
     * @param request Remove operation template request.
     * @return Simple response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public Response removeOperationTemplate(@RequestBody ObjectRequest<OperationTemplateDeleteRequest> request) throws Exception {
        logger.info("OperationTemplateDeleteRequest call received: {}", request);
        service.removeOperationTemplate(request.getRequestObject());
        logger.info("OperationTemplateDeleteRequest succeeded");
        return new Response();
    }

}
