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

package com.wultra.powerauth.fido2.rest.model.entity;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.AuthenticatorDataDeserializer;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.Base64ToByteArrayDeserializer;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.Base64ToStringDeserializer;
import com.wultra.powerauth.fido2.rest.model.converter.serialization.CollectedClientDataDeserializer;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

/**
 * Authenticator assertion response.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class AuthenticatorAssertionResponse {

    @JsonDeserialize(using = CollectedClientDataDeserializer.class)
    private CollectedClientData clientDataJSON;

    @JsonDeserialize(using = AuthenticatorDataDeserializer.class)
    private AuthenticatorData authenticatorData;

    @NotEmpty
    @JsonDeserialize(using = Base64ToByteArrayDeserializer.class)
    private byte[] signature;

    @JsonDeserialize(using = Base64ToStringDeserializer.class)
    private String userHandle;

}
