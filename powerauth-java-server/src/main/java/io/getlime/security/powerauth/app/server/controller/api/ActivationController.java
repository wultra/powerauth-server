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
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to activations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("activationController")
@RequestMapping("/rest/v3/activation")
@Tag(name = "PowerAuth Activation Controller (V3)")
@Slf4j
public class ActivationController {

    private final ActivationServiceBehavior activationServiceBehavior;

    @Autowired
    public ActivationController(ActivationServiceBehavior activationServiceBehavior) {
        this.activationServiceBehavior = activationServiceBehavior;
    }

    /**
     * Init activation.
     *
     * @param request Init activation request.
     * @return Init activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/init")
    public ObjectResponse<InitActivationResponse> initActivation(@RequestBody ObjectRequest<InitActivationRequest> request) throws Exception {
        logger.info("InitActivationRequest received: {}", request);
        final ObjectResponse<InitActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.initActivation(request.getRequestObject()));
        logger.info("InitActivationRequest succeeded: {}", response);
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
    public ObjectResponse<PrepareActivationResponse> prepareActivation(@RequestBody ObjectRequest<PrepareActivationRequest> request) throws Exception {
        logger.info("PrepareActivationRequest received: {}", request);
        final ObjectResponse<PrepareActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.prepareActivation(request.getRequestObject()));
        logger.info("PrepareActivationRequest succeeded");
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
    public ObjectResponse<CreateActivationResponse> createActivation(@RequestBody ObjectRequest<CreateActivationRequest> request) throws Exception {
        logger.info("CreateActivationRequest received: {}", request);
        final ObjectResponse<CreateActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.createActivation(request.getRequestObject()));
        logger.info("CreateActivationRequest succeeded: {}", response);
        return response;
    }

    /**
     * Create activation using recovery code.
     *
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/recovery/create")
    public ObjectResponse<RecoveryCodeActivationResponse> createActivationUsingRecoveryCode(@RequestBody ObjectRequest<RecoveryCodeActivationRequest> request) throws Exception {
        logger.info("RecoveryCodeActivationRequest received: {}", request);
        final ObjectResponse<RecoveryCodeActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.createActivationUsingRecoveryCode(request.getRequestObject()));
        logger.info("RecoveryCodeActivationRequest succeeded: {}", response);
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
    public ObjectResponse<UpdateActivationOtpResponse> updateActivationOtp(@RequestBody ObjectRequest<UpdateActivationOtpRequest> request) throws Exception {
        logger.info("UpdateActivationOtpRequest received: {}", request);
        final ObjectResponse<UpdateActivationOtpResponse> response = new ObjectResponse<>(activationServiceBehavior.updateActivationOtp(request.getRequestObject()));
        logger.info("UpdateActivationOtpRequest succeeded: {}", response);
        return response;
    }

    /**
     * Commit activation.
     *
     * @param request Commit activation request.
     * @return Commit activation response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/commit")
    public ObjectResponse<CommitActivationResponse> commitActivation(@RequestBody ObjectRequest<CommitActivationRequest> request) throws Exception {
        logger.info("CommitActivationRequest received: {}", request);
        final ObjectResponse<CommitActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.commitActivation(request.getRequestObject()));
        logger.info("CommitActivationRequest succeeded: {}", response);
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
    public ObjectResponse<GetActivationStatusResponse> getActivationStatus(@RequestBody ObjectRequest<GetActivationStatusRequest> request) throws Exception {
        logger.info("GetActivationStatusRequest received: {}", request);
        final ObjectResponse<GetActivationStatusResponse> response = new ObjectResponse<>(activationServiceBehavior.getActivationStatus(request.getRequestObject()));
        logger.info("GetActivationStatusResponse succeeded: {}", response);
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
    public ObjectResponse<BlockActivationResponse> blockActivation(@RequestBody ObjectRequest<BlockActivationRequest> request) throws Exception {
        logger.info("BlockActivationRequest received: {}", request);
        final ObjectResponse<BlockActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.blockActivation(request.getRequestObject()));
        logger.info("BlockActivationRequest succeeded: {}", response);
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
    public ObjectResponse<UnblockActivationResponse> unblockActivation(@RequestBody ObjectRequest<UnblockActivationRequest> request) throws Exception {
        logger.info("UnblockActivationRequest received: {}", request);
        final ObjectResponse<UnblockActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.unblockActivation(request.getRequestObject()));
        logger.info("UnblockActivationRequest succeeded: {}", response);
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
    public ObjectResponse<RemoveActivationResponse> removeActivation(@RequestBody ObjectRequest<RemoveActivationRequest> request) throws Exception {
        logger.info("RemoveActivationRequest received: {}", request);
        final ObjectResponse<RemoveActivationResponse> response = new ObjectResponse<>(activationServiceBehavior.removeActivation(request.getRequestObject()));
        logger.info("RemoveActivationRequest succeeded: {}", response);
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
    public ObjectResponse<GetActivationListForUserResponse> getActivationListForUser(@RequestBody ObjectRequest<GetActivationListForUserRequest> request) throws Exception {
        logger.info("GetActivationListForUserRequest received: {}", request);
        final ObjectResponse<GetActivationListForUserResponse> response = new ObjectResponse<>(activationServiceBehavior.getActivationList(request.getRequestObject()));
        logger.info("GetActivationListForUserRequest succeeded: {}", response);
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
        logger.info("UpdateActivationRequest call received: {}", request);
        final ObjectResponse<UpdateActivationNameResponse> response = new ObjectResponse<>(activationServiceBehavior.updateActivationName(request.getRequestObject()));
        logger.info("UpdateActivationRequest succeeded: {}", response);
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
    public ObjectResponse<LookupActivationsResponse> lookupActivations(@RequestBody ObjectRequest<LookupActivationsRequest> request) throws Exception {
        logger.info("LookupActivationsRequest received: {}", request);
        final ObjectResponse<LookupActivationsResponse> response = new ObjectResponse<>(activationServiceBehavior.lookupActivations(request.getRequestObject()));
        logger.info("LookupActivationsRequest succeeded: {}", response);
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
    public ObjectResponse<UpdateStatusForActivationsResponse> updateStatusForActivations(@RequestBody ObjectRequest<UpdateStatusForActivationsRequest> request) throws Exception {
        logger.info("UpdateStatusForActivationsRequest received: {}", request);
        final ObjectResponse<UpdateStatusForActivationsResponse> response = new ObjectResponse<>(activationServiceBehavior.updateStatusForActivation(request.getRequestObject()));
        logger.info("UpdateStatusForActivationsRequest succeeded: {}", response);
        return response;
    }

}
