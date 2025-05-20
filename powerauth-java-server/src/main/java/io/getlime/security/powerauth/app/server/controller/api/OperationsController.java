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
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to operations.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("operationsController")
@RequestMapping("/rest/v3/operation")
@Tag(name = "PowerAuth Operations Controller (V3)")
@Validated
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
    public ObjectResponse<OperationDetailResponse> createOperation(@Valid @RequestBody ObjectRequest<OperationCreateRequest> request) throws Exception {
        final OperationCreateRequest req = request.getRequestObject();
        logger.info("action: createOperation, state: initiated, userId: {}, applications: {}, templateName: {}", req.getUserId(), req.getApplications(), req.getTemplateName());
        logger.debug("action: createOperation, state: initiated, request: {}", request);
        final ObjectResponse<OperationDetailResponse> response = new ObjectResponse<>(service.createOperation(req));
        logger.info("action: createOperation, state: succeeded");
        logger.debug("action: createOperation, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationDetailResponse> operationDetail(@Valid @RequestBody ObjectRequest<OperationDetailRequest> request) throws Exception {
        final OperationDetailRequest req = request.getRequestObject();
        logger.info("action: operationDetail, state: initiated, operationId: {}", req.getOperationId());
        logger.debug("action: operationDetail, state: initiated, request: {}", request);
        final ObjectResponse<OperationDetailResponse> response = new ObjectResponse<>(service.operationDetail(req));
        logger.info("action: operationDetail, state: succeeded");
        logger.debug("action: operationDetail, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Claim operation for a user.
     *
     * @param request Claim operation for a user.
     * @return Get operation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/claim")
    public ObjectResponse<OperationDetailResponse> operationClaim(@Valid @RequestBody ObjectRequest<OperationClaimRequest> request) throws Exception {
        final OperationClaimRequest req = request.getRequestObject();
        logger.info("action: operationClaim, state: initiated, operationId: {}, userId: {}", req.getOperationId(), req.getUserId());
        logger.debug("action: operationClaim, state: initiated, request: {}", request);
        final ObjectResponse<OperationDetailResponse> response = new ObjectResponse<>(service.operationClaim(req));
        logger.info("action: operationClaim, state: succeeded");
        logger.debug("action: operationClaim, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationListResponse> operationList(@Valid @RequestBody ObjectRequest<OperationListForUserRequest> request) throws Exception {
        final OperationListForUserRequest req = request.getRequestObject();
        logger.info("action: operationList, state: initiated, userId: {}, applications: {}", req.getUserId(), req.getApplications());
        logger.debug("action: operationList, state: initiated, request: {}", request);
        final ObjectResponse<OperationListResponse> response = new ObjectResponse<>(service.findAllOperationsForUser(req));
        logger.info("action: operationList, state: succeeded");
        logger.debug("action: operationList, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationListResponse> pendingOperationList(@Valid @RequestBody ObjectRequest<OperationListForUserRequest> request) throws Exception {
        final OperationListForUserRequest req = request.getRequestObject();
        logger.info("action: pendingOperationList, state: initiated, userId: {}, applications: {}", req.getUserId(), req.getApplications());
        logger.debug("action: pendingOperationList, state: initiated, request: {}", request);
        final ObjectResponse<OperationListResponse> response = new ObjectResponse<>(service.findPendingOperationsForUser(req));
        logger.info("action: pendingOperationList, state: succeeded");
        logger.debug("action: pendingOperationList, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationListResponse> findAllOperationsByExternalId(@Valid @RequestBody ObjectRequest<OperationExtIdRequest> request) throws Exception {
        final OperationExtIdRequest req = request.getRequestObject();
        logger.info("action: findAllOperationsByExternalId, state: initiated, externalId: {}, applications: {}", req.getExternalId(), req.getApplications());
        logger.debug("action: findAllOperationsByExternalId, state: initiated, request: {}", request);
        final ObjectResponse<OperationListResponse> response = new ObjectResponse<>(service.findOperationsByExternalId(req));
        logger.info("action: findAllOperationsByExternalId, state: succeeded");
        logger.debug("action: findAllOperationsByExternalId, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationDetailResponse> cancelOperation(@Valid @RequestBody ObjectRequest<OperationCancelRequest> request) throws Exception {
        final OperationCancelRequest req = request.getRequestObject();
        logger.info("action: cancelOperation, state: initiated, operationId: {}", req.getOperationId());
        logger.debug("action: cancelOperation, state: initiated, request: {}", request);
        final ObjectResponse<OperationDetailResponse> response = new ObjectResponse<>(service.cancelOperation(req));
        logger.info("action: cancelOperation, state: succeeded");
        logger.debug("action: cancelOperation, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationUserActionResponse> approveOperation(@Valid @RequestBody ObjectRequest<OperationApproveRequest> request) throws Exception {
        final OperationApproveRequest req = request.getRequestObject();
        logger.info("action: approveOperation, state: initiated, operationId: {}, userId: {}, applicationId: {}", req.getOperationId(), req.getUserId(), req.getApplicationId());
        logger.debug("action: approveOperation, state: initiated, request: {}", request);
        final ObjectResponse<OperationUserActionResponse> response = new ObjectResponse<>(service.attemptApproveOperation(req));
        logger.info("action: approveOperation, state: succeeded, result: {}", response.getResponseObject().getResult());
        logger.debug("action: approveOperation, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationUserActionResponse> failApprovalOperation(@Valid @RequestBody ObjectRequest<OperationFailApprovalRequest> request) throws Exception {
        final OperationFailApprovalRequest req = request.getRequestObject();
        logger.info("action: failApprovalOperation, state: initiated, operationId: {}", req.getOperationId());
        logger.debug("action: failApprovalOperation, state: initiated, request: {}", request);
        final ObjectResponse<OperationUserActionResponse> response = new ObjectResponse<>(service.failApprovalOperation(req));
        logger.info("action: failApprovalOperation, state: succeeded, result: {}", response.getResponseObject().getResult());
        logger.debug("action: failApprovalOperation, state: succeeded, response: {}", response);
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
    public ObjectResponse<OperationUserActionResponse> rejectOperation(@Valid @RequestBody ObjectRequest<OperationRejectRequest> request) throws Exception {
        final OperationRejectRequest req = request.getRequestObject();
        logger.info("action: rejectOperation, state: initiated, operationId: {}, userId: {}, applicationId: {}", req.getOperationId(), req.getUserId(), req.getApplicationId());
        logger.debug("action: rejectOperation, state: initiated, request: {}", request);
        final ObjectResponse<OperationUserActionResponse> response = new ObjectResponse<>(service.rejectOperation(req));
        logger.info("action: rejectOperation, state: succeeded, result: {}", response.getResponseObject().getResult());
        logger.debug("action: rejectOperation, state: succeeded, response: {}", response);
        return response;
    }
}
