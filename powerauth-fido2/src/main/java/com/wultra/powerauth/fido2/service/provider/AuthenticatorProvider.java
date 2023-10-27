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
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;

import java.util.List;

/**
 * Interface for handling authenticator handling logic.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface AuthenticatorProvider {
    AuthenticatorDetail storeAuthenticator(String applicationId, String challenge, AuthenticatorDetail authenticatorDetail) throws Fido2AuthenticationFailedException;
    List<AuthenticatorDetail> findByUserId(String userId, String applicationId) throws Fido2AuthenticationFailedException;
    AuthenticatorDetail findByCredentialId(String credentialId, String applicationId) throws Fido2AuthenticationFailedException;

}
