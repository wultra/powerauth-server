/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package com.wultra.powerauth.fido2.service.provider;

import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorDetail;

import java.util.List;
import java.util.Optional;

/**
 * Interface for handling authenticator handling logic.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface AuthenticatorProvider {

    /**
     * Store an authenticator.
     *
     * @param applicationId Application identifier.
     * @param challenge Registration challenge.
     * @param authenticatorDetail Authenticator detail.
     * @return Authenticator detail.
     * @throws Fido2AuthenticationFailedException Thrown in case storing authenticator fails.
     */
    AuthenticatorDetail storeAuthenticator(String applicationId, String challenge, AuthenticatorDetail authenticatorDetail) throws Fido2AuthenticationFailedException;

    /**
     * Find an authenticator by a user identifier.
     *
     * @param userId User identifier.
     * @param applicationId Application identifier.
     * @return Authenticator detail list.
     * @throws Fido2AuthenticationFailedException Thrown in case lookup fails.
     */
    List<AuthenticatorDetail> findByUserId(String userId, String applicationId) throws Fido2AuthenticationFailedException;

    /**
     * Find an authenticator by a credential identifier.
     *
     * @param credentialId Credential identifier.
     * @param applicationId Application identifier.
     * @return Authenticator detail, if found.
     * @throws Fido2AuthenticationFailedException Thrown in case lookup fails.
     */
    Optional<AuthenticatorDetail> findByCredentialId(String credentialId, String applicationId) throws Fido2AuthenticationFailedException;

}
