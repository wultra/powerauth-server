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
package io.getlime.security.powerauth.app.server.endpoint.v2;

import com.wultra.security.powerauth.client.v2.*;
import io.getlime.security.powerauth.app.server.service.v2.PowerAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

/**
 * Class implementing the SOAP service end-point.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Endpoint(value = "PowerAuth 2.0")
public class PowerAuthEndpoint {

    private static final String NAMESPACE_URI = "http://getlime.io/security/powerauth/v2";

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
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "PrepareActivationRequest")
    @ResponsePayload
    public PrepareActivationResponse prepareActivation(@RequestPayload PrepareActivationRequest request) throws Exception {
        return powerAuthService.prepareActivation(request);
    }

    /**
     * Call {@link PowerAuthService#createActivation(CreateActivationRequest)} method and
     * return the response.
     *
     * @param request Create activation request.
     * @return Create activation response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateActivationRequest")
    @ResponsePayload
    public CreateActivationResponse createActivation(@RequestPayload CreateActivationRequest request) throws Exception {
        return powerAuthService.createActivation(request);
    }

    /**
     * Call {@link PowerAuthService#vaultUnlock(VaultUnlockRequest)} method and
     * return the response.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "VaultUnlockRequest")
    @ResponsePayload
    public VaultUnlockResponse vaultUnlock(@RequestPayload VaultUnlockRequest request) throws Exception {
        return powerAuthService.vaultUnlock(request);
    }

    /**
     * Call {@link PowerAuthService#generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest)} method and
     * return the response.
     *
     * @param request E2E encryption key request.
     * @return E2E encryption key response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetPersonalizedEncryptionKeyRequest")
    @ResponsePayload
    public GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(@RequestPayload GetPersonalizedEncryptionKeyRequest request) throws Exception {
        return powerAuthService.generateE2EPersonalizedEncryptionKey(request);
    }

    /**
     * Call {@link PowerAuthService#generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest)} method and
     * return the response.
     *
     * @param request E2E encryption key request.
     * @return E2E encryption key response.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "GetNonPersonalizedEncryptionKeyRequest")
    @ResponsePayload
    public GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(@RequestPayload GetNonPersonalizedEncryptionKeyRequest request) throws Exception {
        return powerAuthService.generateE2ENonPersonalizedEncryptionKey(request);
    }

    /**
     * Call {@link PowerAuthService#createToken(CreateTokenRequest)}  method and
     * return the response.
     *
     * @param request Create a new token.
     * @return Get response with the new token.
     * @throws Exception In case the service throws exception.
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "CreateTokenRequest")
    @ResponsePayload
    public CreateTokenResponse createToken(@RequestPayload CreateTokenRequest request) throws Exception {
        return powerAuthService.createToken(request);
    }


}
