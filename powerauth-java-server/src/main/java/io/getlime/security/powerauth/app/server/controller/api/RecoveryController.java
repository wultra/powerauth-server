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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
    public ObjectResponse<CreateRecoveryCodeResponse> createRecoveryCodeForUser(@RequestBody ObjectRequest<CreateRecoveryCodeRequest> request) throws Exception {
        logger.info("CreateRecoveryCodeRequest received: {}", request);
        final ObjectResponse<CreateRecoveryCodeResponse> response = new ObjectResponse<>(service.createRecoveryCode(request.getRequestObject()));
        logger.info("CreateRecoveryCodeRequest succeeded: {}", response);
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
    public ObjectResponse<ConfirmRecoveryCodeResponse> confirmRecoveryCode(@RequestBody ObjectRequest<ConfirmRecoveryCodeRequest> request) throws Exception {
        logger.info("ConfirmRecoveryCodeRequest received: {}", request);
        final ObjectResponse<ConfirmRecoveryCodeResponse> response = new ObjectResponse<>(service.confirmRecoveryCode(request.getRequestObject()));
        logger.info("ConfirmRecoveryCodeRequest succeeded: {}", response);
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
    public ObjectResponse<LookupRecoveryCodesResponse> lookupRecoveryCodesRequest(@RequestBody ObjectRequest<LookupRecoveryCodesRequest> request) throws Exception {
        logger.info("LookupRecoveryCodesRequest received: {}", request);
        final ObjectResponse<LookupRecoveryCodesResponse> response = new ObjectResponse<>(service.lookupRecoveryCodes(request.getRequestObject()));
        logger.info("LookupRecoveryCodesRequest succeeded: {}", response);
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
    public ObjectResponse<RevokeRecoveryCodesResponse> revokeRecoveryCodesRequest(@RequestBody ObjectRequest<RevokeRecoveryCodesRequest> request) throws Exception {
        logger.info("RevokeRecoveryCodesRequest received: {}", request);
        final ObjectResponse<RevokeRecoveryCodesResponse> response = new ObjectResponse<>(service.revokeRecoveryCodes(request.getRequestObject()));
        logger.info("RevokeRecoveryCodesRequest succeeded: {}", response);
        return response;
    }

    /**
     * Get the recovery configuration.
     *
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/config/detail")
    public ObjectResponse<GetRecoveryConfigResponse> getRecoveryConfig(@RequestBody ObjectRequest<GetRecoveryConfigRequest> request) throws Exception {
        logger.info("GetRecoveryConfigRequest received: {}", request);
        final ObjectResponse<GetRecoveryConfigResponse> response = new ObjectResponse<>(service.getRecoveryConfig(request.getRequestObject()));
        logger.info("GetRecoveryConfigRequest succeeded: {}", response);
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
    public ObjectResponse<UpdateRecoveryConfigResponse> updateRecoveryConfig(@RequestBody ObjectRequest<UpdateRecoveryConfigRequest> request) throws Exception {
        logger.info("UpdateRecoveryConfigRequest received: {}", request);
        final ObjectResponse<UpdateRecoveryConfigResponse> response = new ObjectResponse<>(service.updateRecoveryConfig(request.getRequestObject()));
        logger.info("UpdateRecoveryConfigRequest succeeded: {}", response);
        return response;
    }

}
