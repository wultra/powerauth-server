/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

package com.wultra.security.powerauth.client.model.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.ToString;

/**
 * Model class representing request for personalized payload for offline signatures.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class CreatePersonalizedOfflineSignaturePayloadRequest {

    private String activationId;
    private String data;

    @Schema(description = "Optional nonce, otherwise it will be generated by PowerAuth server. Needed to be set when proximity check is enabled.")
    private String nonce;

    @Schema(description = "Optional proximity check configuration of TOTP.")
    private ProximityCheck proximityCheck;

    @Data
    public static class ProximityCheck {
        @NotNull
        @ToString.Exclude
        @Schema(description = "Seed for TOTP, base64 encoded.")
        private String seed;

        @Min(1)
        @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Length of the TOTP step in seconds.")
        private int stepLength;
    }

}