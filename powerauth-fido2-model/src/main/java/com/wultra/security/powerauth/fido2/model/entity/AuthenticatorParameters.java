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

package com.wultra.security.powerauth.fido2.model.entity;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Data class representing the parameters obtained from the authenticator registration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class AuthenticatorParameters {

    @NotBlank
    private String credentialId;
    @NotBlank
    private String type;
    private String authenticatorAttachment;
    @NotNull
    private AuthenticatorAttestationResponse response = new AuthenticatorAttestationResponse();
    @NotBlank
    private String relyingPartyId;
    @JsonSetter(nulls = Nulls.SKIP)
    private List<String> allowedOrigins = new ArrayList<>();
    @JsonSetter(nulls = Nulls.SKIP)
    private List<String> allowedTopOrigins = new ArrayList<>();
    private boolean requiresUserVerification;

}
