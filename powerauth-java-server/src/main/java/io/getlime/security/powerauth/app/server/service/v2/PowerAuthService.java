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
package io.getlime.security.powerauth.app.server.service.v2;

import com.wultra.security.powerauth.client.v2.*;
import com.wultra.security.powerauth.client.v3.VerifySignatureRequest;

/**
 * Interface containing all methods that are published by the PowerAuth Server
 * instance. These methods are then used to publish both SOAP and REST interface.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface PowerAuthService {

    /**
     * Receive a PowerAuth Client public key and return own PowerAuth Server public key. The
     * activation with provided ID is in PENDING_COMMIT state after calling this method.
     *
     * @param request Prepare activation request object.
     * @return Prepare activation response.
     * @throws Exception In case of a business logic error.
     */
    PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception;

    /**
     * Create a new activation in PENDING_COMMIT state, without the InitActivation / PrepareActivation cycle.
     * This method receives a PowerAuth Client public key and returns own PowerAuth Server public key.
     * The activation with is in PENDING_COMMIT state after calling this method.
     *
     * Note: This method should be used in case of activation performed directly, without the external
     * master front end application.
     *
     * @param request Create activation request object.
     * @return Create activation response.
     * @throws Exception In case of a business logic error.
     */
    CreateActivationResponse createActivation(CreateActivationRequest request) throws Exception;

    /**
     * Return the data for the vault unlock request. Part of the vault unlock process is performing a signature
     * validation - the rules for blocking activation and counter increment are therefore similar as for the
     * {@link io.getlime.security.powerauth.app.server.service.v3.PowerAuthService#verifySignature(VerifySignatureRequest)} method. For vaultUnlock, however,
     * counter is incremented by 2 - one for signature validation, second for the transport key derivation.
     *
     * @param request Vault unlock request object.
     * @return Vault unlock response.
     * @throws Exception In case of a business logic error.
     */
    VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception;

    /**
     * Generate an activation specific transport key with given index for the purpose of personalized end-to-end encryption.
     * @param request Request with an activation ID and optional session index.
     * @return Response with derived transport key and its session index.
     * @throws Exception In case of a business logic error.
     */
    GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest request) throws Exception;

    /**
     * Generate an application specific transport key with given index for the purpose of non-personalized end-to-end encryption.
     * @param request Request with application ID and optional session index.
     * @return Response with derived transport key and its session index.
     * @throws Exception In case of a business logic error.
     */
    GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) throws Exception;

    /**
     * Creates a new token for simple token-based device authentication.
     * @param request Request with information required to issue the token.
     * @return Response with the token information.
     * @throws Exception In case of a business logic error.
     */
    CreateTokenResponse createToken(CreateTokenRequest request) throws Exception;

}
