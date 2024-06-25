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

package com.wultra.powerauth.fido2.rest.model.request;

import com.wultra.powerauth.fido2.rest.model.entity.AttestationObject;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorData;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import com.wultra.security.powerauth.fido2.model.request.AssertionVerificationRequest;
import lombok.Builder;
import lombok.NonNull;

/**
 * Wraps {@link AssertionVerificationRequest}, deserialized {@link CollectedClientData} and {@link AttestationObject}.
 *
 * @param clientDataJSON Deserialized {@code assertionVerificationRequest.getResponse().getClientDataJSON()}.
 * @param authenticatorData Deserialize {@code assertionVerificationRequest.getResponse().getAuthenticatorData()}.
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Builder
public record AssertionVerificationRequestWrapper(
        @NonNull
        AssertionVerificationRequest assertionVerificationRequest,
        @NonNull
        CollectedClientData clientDataJSON,
        @NonNull
        AuthenticatorData authenticatorData
) {
}
