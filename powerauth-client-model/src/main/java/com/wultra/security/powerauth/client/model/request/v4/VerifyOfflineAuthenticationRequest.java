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

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.ToString;

import java.math.BigInteger;

/**
 * Model class representing request for offline authentication code verification (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class VerifyOfflineAuthenticationRequest {

    @Schema(description = "Activation identifier")
    @NotBlank(message = "Activation ID must not be empty when verifying offline authentication")
    private String activationId;

    @Schema(description = "Authentication data")
    @NotNull(message = "Parameter data must not be null when verifying authentication")
    private String data;

    @Schema(description = "Authentication code")
    @NotBlank(message = "Authentication code must not be empty when verifying authentication")
    @ToString.Exclude
    private String authenticationCode;

    @Schema(description = "Authentication component length")
    private BigInteger componentLength;

    @Schema(description = "Whether biometric factor is allowed")
    private boolean allowBiometry;

    @Schema(description = "Optional proximity check configuration of TOTP.")
    private VerifyProximityCheck proximityCheck;

    @Data
    public static class VerifyProximityCheck {
        @NotNull
        @ToString.Exclude
        @Schema(description = "Seed for TOTP, base64 encoded.")
        private String seed;

        @Min(1)
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Length of the TOTP step in seconds.")
        private int stepLength;

        @Min(0)
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "How many backward steps should be validated. Zero means current one only.")
        private int stepCount;
    }

}
