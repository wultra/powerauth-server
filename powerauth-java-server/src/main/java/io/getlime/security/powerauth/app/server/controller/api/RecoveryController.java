/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
import io.getlime.security.powerauth.app.server.service.behavior.tasks.RecoveryServiceBehavior;
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
 * Controller managing the endpoints related to recovery codes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("RecoveryController")
@RequestMapping("/rest/v3/recovery")
@Tag(name = "PowerAuth Controller V3")
@Validated
@Slf4j
public class RecoveryController {

    private final RecoveryServiceBehavior service;

    @Autowired
    public RecoveryController(RecoveryServiceBehavior service) {
        this.service = service;
    }

    /**
     * Create the recovery code.
     *
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateRecoveryCodeResponse> createRecoveryCodeForUser(@Valid @RequestBody ObjectRequest<CreateRecoveryCodeRequest> request) throws Exception {
        final CreateRecoveryCodeRequest req = request.getRequestObject();
        logger.info("action: createRecoveryCodeForUser, state: initiated, applicationId: {}, userId: {}", req.getApplicationId(), req.getUserId());
        logger.debug("action: createRecoveryCodeForUser, state: initiated, request: {}", request);
        final ObjectResponse<CreateRecoveryCodeResponse> response = new ObjectResponse<>(service.createRecoveryCode(req));
        logger.info("action: createRecoveryCodeForUser, state: succeeded");
        logger.debug("action: createRecoveryCodeForUser, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Confirm recovery code.
     *
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/confirm")
    public ObjectResponse<ConfirmRecoveryCodeResponse> confirmRecoveryCode(@Valid @RequestBody ObjectRequest<ConfirmRecoveryCodeRequest> request) throws Exception {
        final ConfirmRecoveryCodeRequest req = request.getRequestObject();
        logger.info("action: confirmRecoveryCode, state: initiated, activationId: {}, applicationKey: {}", req.getActivationId(), req.getApplicationKey());
        logger.debug("action: confirmRecoveryCode, state: initiated, request: {}", request);
        final ObjectResponse<ConfirmRecoveryCodeResponse> response = new ObjectResponse<>(service.confirmRecoveryCode(req));
        logger.info("action: confirmRecoveryCode, state: succeeded");
        logger.debug("action: confirmRecoveryCode, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Lookup recovery codes.
     *
     * @param request Lookup recovery codes request.
     * @return Lookup recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/lookup")
    public ObjectResponse<LookupRecoveryCodesResponse> lookupRecoveryCodesRequest(@Valid @RequestBody ObjectRequest<LookupRecoveryCodesRequest> request) throws Exception {
        final LookupRecoveryCodesRequest req = request.getRequestObject();
        logger.info("action: lookupRecoveryCodesRequest, state: initiated, userId: {}, activationId: {}", req.getUserId(), req.getActivationId());
        logger.debug("action: lookupRecoveryCodesRequest, state: initiated, request: {}", request);
        final ObjectResponse<LookupRecoveryCodesResponse> response = new ObjectResponse<>(service.lookupRecoveryCodes(req));
        logger.info("action: lookupRecoveryCodesRequest, state: succeeded");
        logger.debug("action: lookupRecoveryCodesRequest, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Revoke recovery codes.
     *
     * @param request Revoke recovery codes request.
     * @return Revoke recovery code response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/revoke")
    public ObjectResponse<RevokeRecoveryCodesResponse> revokeRecoveryCodesRequest(@Valid @RequestBody ObjectRequest<RevokeRecoveryCodesRequest> request) throws Exception {
        final RevokeRecoveryCodesRequest req = request.getRequestObject();
        logger.info("action: revokeRecoveryCodesRequest, state: initiated, recoveryCodeIds: {}", req.getRecoveryCodeIds());
        logger.debug("action: revokeRecoveryCodesRequest, state: initiated, request: {}", request);
        final ObjectResponse<RevokeRecoveryCodesResponse> response = new ObjectResponse<>(service.revokeRecoveryCodes(req));
        logger.info("action: revokeRecoveryCodesRequest, state: succeeded");
        logger.debug("action: revokeRecoveryCodesRequest, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Get the recovery configuration or create a new one if it does not exist yet.
     *
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/config/detail")
    public ObjectResponse<GetRecoveryConfigResponse> getRecoveryConfig(@Valid @RequestBody ObjectRequest<GetRecoveryConfigRequest> request) throws Exception {
        final GetRecoveryConfigRequest req = request.getRequestObject();
        logger.info("action: getRecoveryConfig, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: getRecoveryConfig, state: initiated, request: {}", request);
        final ObjectResponse<GetRecoveryConfigResponse> response = new ObjectResponse<>(service.getRecoveryConfig(req));
        logger.info("action: getRecoveryConfig, state: succeeded");
        logger.debug("action: getRecoveryConfig, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Update recovery configuration.
     *
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/config/update")
    public ObjectResponse<UpdateRecoveryConfigResponse> updateRecoveryConfig(@Valid @RequestBody ObjectRequest<UpdateRecoveryConfigRequest> request) throws Exception {
        final UpdateRecoveryConfigRequest req = request.getRequestObject();
        logger.info("action: updateRecoveryConfig, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: updateRecoveryConfig, state: initiated, request: {}", request);
        final ObjectResponse<UpdateRecoveryConfigResponse> response = new ObjectResponse<>(service.updateRecoveryConfig(req));
        logger.info("action: updateRecoveryConfig, state: succeeded");
        logger.debug("action: updateRecoveryConfig, state: succeeded, response: {}", response);
        return response;
    }

}
