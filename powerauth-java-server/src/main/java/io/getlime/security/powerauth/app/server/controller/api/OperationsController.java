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
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OperationServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to operations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("operationsController")
@RequestMapping("/rest/v3/operation")
@Tag(name = "PowerAuth Operations Controller (V3)")
@Slf4j
public class OperationsController {

    private final OperationServiceBehavior service;

    @Autowired
    public OperationsController(OperationServiceBehavior service) {
        this.service = service;
    }

    /**
     * Create a new operation.
     *
     * @param request Create a new operation request.
     * @return Create operation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<OperationDetailResponse> createOperation(@RequestBody ObjectRequest<OperationCreateRequest> request) throws Exception {
        logger.info("OperationCreateRequest received: {}", request);
        final ObjectResponse<OperationDetailResponse> response = new ObjectResponse<>("OK", service.createOperation(request.getRequestObject()));
        logger.info("OperationCreateRequest succeeded: {}", response);
        return response;
    }

    /**
     * Get operation detail.
     *
     * @param request Get operation request.
     * @return Get operation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/detail")
    public ObjectResponse<OperationDetailResponse> operationDetail(@RequestBody ObjectRequest<OperationDetailRequest> request) throws Exception {
        logger.info("OperationDetailRequest received: {}", request);
        final ObjectResponse<OperationDetailResponse> response = new ObjectResponse<>("OK", service.operationDetail(request.getRequestObject()));
        logger.info("OperationDetailRequest succeeded: {}", response);
        return response;
    }

    /**
     * Find all operations for given user.
     *
     * @param request Get operation list request.
     * @return Get operation list response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<OperationListResponse> operationList(@RequestBody ObjectRequest<OperationListForUserRequest> request) throws Exception {
        logger.info("OperationListForUserRequest received: {}", request);
        final ObjectResponse<OperationListResponse> response = new ObjectResponse<>("OK", service.findAllOperationsForUser(request.getRequestObject()));
        logger.info("OperationListForUserRequest succeeded: {}", response);
        return response;
    }

    /**
     * Get pending operations for the user.
     *
     * @param request Get pending operation list request.
     * @return Get pending operation list response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list/pending")
    public ObjectResponse<OperationListResponse> pendingOperationList(@RequestBody ObjectRequest<OperationListForUserRequest> request) throws Exception {
        logger.info("OperationListForUserRequest received: {}", request);
        final ObjectResponse<OperationListResponse> response = new ObjectResponse<>("OK", service.findPendingOperationsForUser(request.getRequestObject()));
        logger.info("OperationListForUserRequest succeeded: {}", response);
        return response;
    }

    /**
     * Find operations by external ID.
     *
     * @param request Get operations based on external ID request.
     * @return Get operation list response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list/external")
    public ObjectResponse<OperationListResponse> findAllOperationsByExternalId(@RequestBody ObjectRequest<OperationExtIdRequest> request) throws Exception {
        logger.info("findAllOperationsByExternalId received: {}", request);
        final ObjectResponse<OperationListResponse> response = new ObjectResponse<>("OK", service.findOperationsByExternalId(request.getRequestObject()));
        logger.info("findAllOperationsByExternalId succeeded: {}", response);
        return response;
    }

    /**
     * Cancel operation.
     *
     * @param request Cancel operation request.
     * @return Cancel operation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/cancel")
    public ObjectResponse<OperationDetailResponse> cancelOperation(@RequestBody ObjectRequest<OperationCancelRequest> request) throws Exception {
        logger.info("OperationCancelRequest received: {}", request);
        final ObjectResponse<OperationDetailResponse> response = new ObjectResponse<>("OK", service.cancelOperation(request.getRequestObject()));
        logger.info("OperationCancelRequest succeeded: {}", response);
        return response;
    }

    /**
     * Attempt to approve an operation.
     *
     * @param request Approve operation request.
     * @return Approve operation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/approve")
    public ObjectResponse<OperationUserActionResponse> approveOperation(@RequestBody ObjectRequest<OperationApproveRequest> request) throws Exception {
        logger.info("OperationApproveRequest received: {}", request);
        final ObjectResponse<OperationUserActionResponse> response = new ObjectResponse<>("OK", service.attemptApproveOperation(request.getRequestObject()));
        logger.info("OperationApproveRequest succeeded: {}", response);
        return response;
    }

    /**
     * Fail operation approval.
     *
     * @param request Fail approval operation request.
     * @return Fail approval operation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/approve/fail")
    public ObjectResponse<OperationUserActionResponse> failApprovalOperation(@RequestBody ObjectRequest<OperationFailApprovalRequest> request) throws Exception {
        logger.info("OperationFailApprovalRequest received: {}", request);
        final ObjectResponse<OperationUserActionResponse> response = new ObjectResponse<>("OK", service.failApprovalOperation(request.getRequestObject()));
        logger.info("OperationFailApprovalRequest succeeded: {}", response);
        return response;
    }

    /**
     * Reject the operation.
     *
     * @param request Reject operation request.
     * @return Reject operation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/reject")
    public ObjectResponse<OperationUserActionResponse> rejectOperation(@RequestBody ObjectRequest<OperationRejectRequest> request) throws Exception {
        logger.info("OperationRejectRequest received: {}", request);
        final ObjectResponse<OperationUserActionResponse> response = new ObjectResponse<>("OK", service.rejectOperation(request.getRequestObject()));
        logger.info("OperationRejectRequest succeeded: {}", response);
        return response;
    }
}
