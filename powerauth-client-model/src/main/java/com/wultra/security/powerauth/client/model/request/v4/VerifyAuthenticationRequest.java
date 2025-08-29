/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.client.model.request.v4;

import com.wultra.security.powerauth.client.model.annotation.Base64Encoded;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing request for authentication code verification (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class VerifyAuthenticationRequest {

    @Schema(description = "Activation identifier")
    @NotBlank(message = "Activation ID must not be empty when verifying authentication")
    private String activationId;

    @Schema(description = "Application key")
    @NotBlank(message = "Application key must not be empty when verifying authentication")
    private String applicationKey;

    @Schema(description = "Signed data")
    @NotNull(message = "Parameter data must not be null when verifying authentication")
    private String data;

    @Schema(description = "Authentication code")
    @NotBlank(message = "Authentication code must not be empty when verifying authentication")
    @Base64Encoded(message = "Authentication code must be a valid Base-64 encoded string")
    @ToString.Exclude
    private String authenticationCode;

    @Schema(description = "Authentication code type")
    @NotNull(message = "Authentication code type must not be null when verifying authentication")
    private AuthenticationCodeType authenticationCodeType;

    @Schema(description = "Authentication protocol version")
    @NotBlank(message = "Authentication version must not be empty when verifying authentication")
    private String authenticationVersion;

    @Schema(description = "Forced authentication protocol version used during protocol upgrade")
    private Integer forcedAuthenticationVersion;

    @Schema(description = "Activation states which are allowed when verifying authentication")
    private List<@NotNull ActivationStatus> allowedStates = new ArrayList<>();

}
