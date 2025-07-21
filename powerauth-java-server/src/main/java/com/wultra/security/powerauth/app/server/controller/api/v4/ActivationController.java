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
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationInitServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.ActivationCreateServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.ActivationStatusServiceBehavior;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.ConfirmActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.request.v4.PrepareActivationRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreateActivationResponse;
import com.wultra.security.powerauth.client.model.response.v4.PrepareActivationResponse;
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
 * Controller managing the endpoints related to activations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("activationControllerV4")
@RequestMapping("/rest/v4/activation")
@Tag(name = "PowerAuth Activation Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class ActivationController {

    private final ActivationServiceBehavior activationServiceBehavior;
    private final ActivationCreateServiceBehavior activationCreateServiceBehavior;
    private final ActivationInitServiceBehavior activationInitServiceBehavior;
    private final ActivationStatusServiceBehavior activationStatusServiceBehavior;

    /**
     * Init activation.
     *
     * @param request Init activation request.
     * @return Init activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/init")
    public ObjectResponse<InitActivationResponse> initActivation(@Valid @RequestBody ObjectRequest<InitActivationRequest> request) throws Exception {
        final InitActivationRequest req = request.getRequestObject();
        logger.info("action: initActivation, state: initiated, userId: {}, application: {}", req.getUserId(), req.getApplicationId());
        logger.debug("action: initActivation, state: initiated, request: {}", request);
        final ObjectResponse<InitActivationResponse> response = new ObjectResponse<>(activationInitServiceBehavior.initActivation(req));
        logger.info("action: initActivation, state: succeeded");
        logger.debug("action: initActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Prepare activation.
     *
     * @param request Prepare activation request.
     * @return Prepare activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/prepare")
    public ObjectResponse<PrepareActivationResponse> prepareActivation(@Valid @RequestBody ObjectRequest<PrepareActivationRequest> request) throws Exception {
        final PrepareActivationRequest req = request.getRequestObject();
        logger.info("action: prepareActivation, state: initiated, applicationKey: {}, requestTimestamp: {}", req.getApplicationKey(), req.getTimestamp());
        logger.debug("action: prepareActivation, state: initiated, request: {}", request);
        final ObjectResponse<PrepareActivationResponse> response = new ObjectResponse<>(activationCreateServiceBehavior.prepareActivation(req));
        logger.info("action: prepareActivation, state: succeeded");
        logger.debug("action: prepareActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Create activation.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateActivationResponse> createActivation(@Valid @RequestBody ObjectRequest<CreateActivationRequest> request) throws Exception {
        final com.wultra.security.powerauth.client.model.request.v4.CreateActivationRequest req = request.getRequestObject();
        logger.info("action: createActivation, state: initiated, userId: {}, applicationKey: {}, requestTimestamp: {}", req.getUserId(), req.getApplicationKey(), req.getTimestamp());
        logger.debug("action: createActivation, state: initiated, request: {}", request);
        final ObjectResponse<CreateActivationResponse> response = new ObjectResponse<>(activationCreateServiceBehavior.createActivation(req));
        logger.info("action: createActivation, state: succeeded");
        logger.debug("action: createActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Update activation OTP.
     *
     * @param request Update activation OTP request.
     * @return Update activation OTP response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/otp/update")
    public ObjectResponse<UpdateActivationOtpResponse> updateActivationOtp(@Valid @RequestBody ObjectRequest<UpdateActivationOtpRequest> request) throws Exception {
        final UpdateActivationOtpRequest req = request.getRequestObject();
        logger.info("action: updateActivationOtp, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: updateActivationOtp, state: initiated, request: {}", request);
        final ObjectResponse<UpdateActivationOtpResponse> response = new ObjectResponse<>(activationServiceBehavior.updateActivationOtp(req));
        logger.info("action: updateActivationOtp, state: succeeded");
        logger.debug("action: updateActivationOtp, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Confirm activation.
     *
     * @param request Confirm activation request.
     * @return Confirm activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/confirm")
    public Response confirmActivation(@Valid @RequestBody ObjectRequest<ConfirmActivationRequest> request) throws Exception {
        final ConfirmActivationRequest req = request.getRequestObject();
        logger.info("action: confirmActivation, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: confirmActivation, state: initiated, request: {}", request);
        activationServiceBehavior.confirmActivation(req);
        logger.info("action: confirmActivation, state: succeeded");
        logger.debug("action: confirmActivation, state: succeeded, response: empty");
        return new Response();
    }

    /**
     * Commit activation.
     *
     * @param request Commit activation request.
     * @return Commit activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/commit")
    public ObjectResponse<CommitActivationResponse> commitActivation(@Valid @RequestBody ObjectRequest<CommitActivationRequest> request) throws Exception {
        final CommitActivationRequest req = request.getRequestObject();
        logger.info("action: commitActivation, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: commitActivation, state: initiated, request: {}", request);
        final ObjectResponse<CommitActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.commitActivation(req));
        logger.info("action: commitActivation, state: succeeded");
        logger.debug("action: commitActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Get activation status.
     *
     * @param request Activation status request.
     * @return Activation status response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/status")
    public ObjectResponse<GetActivationStatusResponse> getActivationStatus(@Valid @RequestBody ObjectRequest<GetActivationStatusRequest> request) throws Exception {
        final GetActivationStatusRequest req = request.getRequestObject();
        logger.info("action: getActivationStatus, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: getActivationStatus, state: initiated, request: {}", request);
        final ObjectResponse<GetActivationStatusResponse> response = new ObjectResponse<>(activationStatusServiceBehavior.getActivationStatus(req));
        logger.info("action: getActivationStatus, state: succeeded");
        logger.debug("action: getActivationStatus, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Block activation.
     *
     * @param request Block activation request.
     * @return Block activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/block")
    public ObjectResponse<BlockActivationResponse> blockActivation(@Valid @RequestBody ObjectRequest<BlockActivationRequest> request) throws Exception {
        final BlockActivationRequest req = request.getRequestObject();
        logger.info("action: blockActivation, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: blockActivation, state: initiated, request: {}", request);
        final ObjectResponse<BlockActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.blockActivation(req));
        logger.info("action: blockActivation, state: succeeded");
        logger.debug("action: blockActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Unblock activation.
     *
     * @param request Unblock activation request.
     * @return Unblock activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/unblock")
    public ObjectResponse<UnblockActivationResponse> unblockActivation(@Valid @RequestBody ObjectRequest<UnblockActivationRequest> request) throws Exception {
        final UnblockActivationRequest req = request.getRequestObject();
        logger.info("action: unblockActivation, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: unblockActivation, state: initiated, request: {}", request);
        final ObjectResponse<UnblockActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.unblockActivation(req));
        logger.info("action: unblockActivation, state: succeeded");
        logger.debug("action: unblockActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Remove activation.
     *
     * @param request Remove activation request.
     * @return Remove activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveActivationResponse> removeActivation(@Valid @RequestBody ObjectRequest<RemoveActivationRequest> request) throws Exception {
        final RemoveActivationRequest req = request.getRequestObject();
        logger.info("action: removeActivation, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: removeActivation, state: initiated, request: {}", request);
        final ObjectResponse<RemoveActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.removeActivation(req));
        logger.info("action: removeActivation, state: succeeded");
        logger.debug("action: removeActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Get activation list for provided user.
     *
     * @param request This is an {@link ObjectRequest} that contains a {@link GetActivationListForUserRequest}, which
     *                includes the user identifier and application identifier for which to retrieve activations.
     * @return This endpoint returns an {@link ObjectResponse} that contains a {@link GetActivationListForUserResponse},
     *         which includes the list of activations for the given user and application ID.
     * @throws Exception In case the service throws an exception, it will be propagated and should be handled by the caller.
     */
    @PostMapping("/list")
    public ObjectResponse<GetActivationListForUserResponse> getActivationListForUser(@Valid @RequestBody ObjectRequest<GetActivationListForUserRequest> request) throws Exception {
        final GetActivationListForUserRequest req = request.getRequestObject();
        logger.info("action: getActivationListForUser, state: initiated, userId: {}", req.getUserId());
        logger.debug("action: getActivationListForUser, state: initiated, request: {}", request);
        final ObjectResponse<GetActivationListForUserResponse> response = new ObjectResponse<>(activationServiceBehavior.getActivationList(req));
        logger.info("action: getActivationListForUser, state: succeeded");
        logger.debug("action: getActivationListForUser, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Update the activation name.
     *
     * @param request This is an {@link ObjectRequest} that contains a {@link UpdateActivationNameRequest}.
     * @return This endpoint returns an {@link ObjectResponse} that contains a {@link UpdateActivationNameResponse}.
     * @throws Exception In case the service throws an exception, it will be propagated and should be handled by the caller.
     */
    @PostMapping("/name/update")
    public ObjectResponse<UpdateActivationNameResponse> updateActivation(@Valid @RequestBody ObjectRequest<UpdateActivationNameRequest> request) throws Exception {
        final UpdateActivationNameRequest req = request.getRequestObject();
        logger.info("action: updateActivation, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: updateActivation, state: initiated, request: {}", request);
        final ObjectResponse<UpdateActivationNameResponse> response = new ObjectResponse<>(activationServiceBehavior.updateActivationName(req));
        logger.info("action: updateActivation, state: succeeded");
        logger.debug("action: updateActivation, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Lookup activation according to specified query.
     *
     * @param request Lookup activations request.
     * @return Lookup activations response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/lookup")
    public ObjectResponse<LookupActivationsResponse> lookupActivations(@Valid @RequestBody ObjectRequest<LookupActivationsRequest> request) throws Exception {
        final LookupActivationsRequest req = request.getRequestObject();
        logger.info("action: lookupActivations, state: initiated, userIds: {}", req.getUserIds());
        logger.debug("action: lookupActivations, state: initiated, request: {}", request);
        final ObjectResponse<LookupActivationsResponse> response = new ObjectResponse<>(activationServiceBehavior.lookupActivations(req));
        logger.info("action: lookupActivations, state: succeeded");
        logger.debug("action: lookupActivations, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Update status for activations matching provided query.
     *
     * @param request Update status for activations request.
     * @return Update status for activations response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/status/update")
    public ObjectResponse<UpdateStatusForActivationsResponse> updateStatusForActivations(@Valid @RequestBody ObjectRequest<UpdateStatusForActivationsRequest> request) throws Exception {
        final UpdateStatusForActivationsRequest req = request.getRequestObject();
        logger.info("action: updateStatusForActivations, state: initiated, activationIds: {}", req.getActivationIds());
        logger.debug("action: updateStatusForActivations, state: initiated, request: {}", request);
        final ObjectResponse<UpdateStatusForActivationsResponse> response = new ObjectResponse<>(activationServiceBehavior.updateStatusForActivation(req));
        logger.info("action: updateStatusForActivations, state: succeeded");
        logger.debug("action: updateStatusForActivations, state: succeeded, response: {}", response);
        return response;
    }

}
