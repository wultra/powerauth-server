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
package io.getlime.security.powerauth.app.server.controller.v2;

import io.getlime.security.powerauth.app.server.controller.RESTRequestWrapper;
import io.getlime.security.powerauth.app.server.controller.RESTResponseWrapper;
import io.getlime.security.powerauth.app.server.service.v2.PowerAuthService;
import io.getlime.security.powerauth.v2.*;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Class implementing the RESTful controller for PowerAuth service.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("restControllerV2")
@RequestMapping(value = "/rest/v2")
@Api(tags={"PowerAuth Controller V2"})
public class PowerAuthController {

    private PowerAuthService powerAuthService;

    @Autowired
    public void setPowerAuthService(PowerAuthService powerAuthService) {
        this.powerAuthService = powerAuthService;
    }

    /**
     * Call {@link PowerAuthService#prepareActivation(PrepareActivationRequest)} method and
     * return the response.
     *
     * @param request Prepare activation request.
     * @return Prepare activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/prepare", method = RequestMethod.POST)
    public RESTResponseWrapper<PrepareActivationResponse> prepareActivation(@RequestBody RESTRequestWrapper<PrepareActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.prepareActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createActivation(CreateActivationRequest)}  method and
     * return the response.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/create", method = RequestMethod.POST)
    public RESTResponseWrapper<CreateActivationResponse> createActivation(@RequestBody RESTRequestWrapper<CreateActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createActivation(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#vaultUnlock(VaultUnlockRequest)} method and
     * return the response.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/vault/unlock", method = RequestMethod.POST)
    public RESTResponseWrapper<VaultUnlockResponse> vaultUnlock(@RequestBody RESTRequestWrapper<VaultUnlockRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.vaultUnlock(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest)} method and
     * return the response.
     *
     * @param request E2E encryption key request.
     * @return E2E encryption key response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/activation/encryption/key/create", method = RequestMethod.POST)
    public RESTResponseWrapper<GetPersonalizedEncryptionKeyResponse> generateE2EEncryptionKey(@RequestBody RESTRequestWrapper<GetPersonalizedEncryptionKeyRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.generateE2EPersonalizedEncryptionKey(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest)} method and
     * return the response.
     *
     * @param request E2E encryption key request.
     * @return E2E encryption key response.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/application/encryption/key/create", method = RequestMethod.POST)
    public RESTResponseWrapper<GetNonPersonalizedEncryptionKeyResponse> generateE2ENonPersonalizedEncryptionKey(@RequestBody RESTRequestWrapper<GetNonPersonalizedEncryptionKeyRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.generateE2ENonPersonalizedEncryptionKey(request.getRequestObject()));
    }

    /**
     * Call {@link PowerAuthService#createToken(CreateTokenRequest)} method and
     * return the response.
     *
     * @param request Create a new token for a simple token-based authentication.
     * @return Response with the new token information.
     * @throws Exception In case the service throws exception.
     */
    @RequestMapping(value = "/token/create", method = RequestMethod.POST)
    public RESTResponseWrapper<CreateTokenResponse> createToken(@RequestBody RESTRequestWrapper<CreateTokenRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.createToken(request.getRequestObject()));
    }

}
