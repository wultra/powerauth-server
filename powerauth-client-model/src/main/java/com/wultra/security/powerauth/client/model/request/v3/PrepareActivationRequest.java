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

package com.wultra.security.powerauth.client.model.request.v3;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.ToString;

/**
 * Model class representing request for activation preparation request (V3).
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class PrepareActivationRequest {

    @Schema(description = "Activation code")
    @NotBlank(message = "Activation code must not be empty when preparing activation")
    private String activationCode;

    @Schema(description = "Application key")
    @NotBlank(message = "Application key must not be empty when preparing activation")
    private String applicationKey;

    @Schema(description = "Identifier of the temporary key for encryption")
    private String temporaryKeyId;

    @Schema(description = "Ephemeral public key used in encryption")
    @NotBlank(message = "Ephemeral public key must not be empty when preparing activation")
    private String ephemeralPublicKey;

    @Schema(description = "Encrypted data")
    @NotBlank(message = "Encrypted data must not be empty when preparing activation")
    private String encryptedData;

    @Schema(description = "Value of MAC used in encryption")
    @NotBlank(message = "Value of MAC must not be empty when preparing activation")
    private String mac;

    @Schema(description = "Nonce value")
    @ToString.Exclude
    private String nonce;

    @Schema(description = "Cryptography protocol version")
    @NotBlank(message = "Protocol version must not be empty when preparing activation")
    private String protocolVersion;

    @Schema(description = "Timestamp value used in encryption")
    private Long timestamp;

}
