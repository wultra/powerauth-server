/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.OperationTemplateServiceBehavior;
import com.wultra.security.powerauth.client.model.request.v4.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDeleteRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDetailRequest;
import com.wultra.security.powerauth.client.model.request.v4.OperationTemplateUpdateRequest;
import com.wultra.security.powerauth.client.model.response.v4.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.client.model.response.v4.OperationTemplateListResponse;
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
 * Controller managing the endpoints related to operation templates.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("operationTemplatesControllerV4")
@RequestMapping( "/rest/v4/operation/template")
@Tag(name = "PowerAuth Operation Templates Controller")
@AllArgsConstructor
@Validated
@Slf4j
public class OperationTemplatesController {

    private final OperationTemplateServiceBehavior service;

    /**
     * Get all operation templates.
     *
     * @return Get operation templates response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<OperationTemplateListResponse> getOperationTemplateList() throws Exception {
        logger.info("action: getOperationTemplateList, state: initiated");
        logger.debug("action: getOperationTemplateList, state: initiated, request: empty");
        final ObjectResponse<OperationTemplateListResponse> response = new ObjectResponse<>(service.getAllTemplates());
        logger.info("action: getOperationTemplateList, state: succeeded");
        logger.debug("action: getOperationTemplateList, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationTemplateDetailResponse> getOperationTemplateDetail(@Valid @RequestBody ObjectRequest<OperationTemplateDetailRequest> request) throws Exception {
        final OperationTemplateDetailRequest req = request.getRequestObject();
        logger.info("action: getOperationTemplateDetail, state: initiated, templateId: {}", req.getId());
        logger.debug("action: getOperationTemplateDetail, state: initiated, request: {}", request);
        final ObjectResponse<OperationTemplateDetailResponse> response = new ObjectResponse<>(service.getTemplateDetail(req));
        logger.info("action: getOperationTemplateDetail, state: succeeded");
        logger.debug("action: getOperationTemplateDetail, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationTemplateDetailResponse> createOperationTemplate(@Valid @RequestBody ObjectRequest<OperationTemplateCreateRequest> request) throws Exception {
        final OperationTemplateCreateRequest req = request.getRequestObject();
        logger.info("action: createOperationTemplate, state: initiated, templateName: {}, operationType: {}", req.getTemplateName(), req.getOperationType());
        logger.debug("action: createOperationTemplate, state: initiated, request: {}", request);
        final ObjectResponse<OperationTemplateDetailResponse> response = new ObjectResponse<>(service.createOperationTemplate(req));
        logger.info("action: createOperationTemplate, state: succeeded");
        logger.debug("action: createOperationTemplate, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationTemplateDetailResponse> updateOperationTemplate(@Valid @RequestBody ObjectRequest<OperationTemplateUpdateRequest> request) throws Exception {
        final OperationTemplateUpdateRequest req = request.getRequestObject();
        logger.info("action: updateOperationTemplate, state: initiated, templateId: {}", req.getId());
        logger.debug("action: updateOperationTemplate, state: initiated, request: {}", request);
        final ObjectResponse<OperationTemplateDetailResponse> response = new ObjectResponse<>(service.updateOperationTemplate(req));
        logger.info("action: updateOperationTemplate, state: succeeded");
        logger.debug("action: updateOperationTemplate, state: succeeded, response: {}", response);
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
    public Response removeOperationTemplate(@Valid @RequestBody ObjectRequest<OperationTemplateDeleteRequest> request) throws Exception {
        final OperationTemplateDeleteRequest req = request.getRequestObject();
        logger.info("action: removeOperationTemplate, state: initiated, templateId: {}", req.getId());
        logger.debug("action: removeOperationTemplate, state: initiated, request: {}", request);
        service.removeOperationTemplate(req);
        logger.info("action: removeOperationTemplate, state: succeeded");
        logger.debug("action: removeOperationTemplate, state: succeeded, response: empty");
        return new Response();
    }

}
