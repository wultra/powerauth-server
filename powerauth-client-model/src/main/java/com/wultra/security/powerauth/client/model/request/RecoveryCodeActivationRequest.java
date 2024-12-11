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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.ToString;

/**
 * Model class representing request for activation via recovery code.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class RecoveryCodeActivationRequest {

    @Schema(description = "Whether recovery codes should be generated")
    private Boolean generateRecoveryCodes;

    @Schema(description = "Recovery code value used for activation")
    @NotBlank(message = "Recovery code value must not be empty when creating activation using recovery code")
    @ToString.Exclude
    private String recoveryCode;

    @Schema(description = "Recovery PUK value used for activation")
    @NotBlank(message = "Recovery PUK value must not be empty when creating activation using recovery code")
    @ToString.Exclude
    private String puk;

    @Schema(description = "Application key")
    @NotBlank(message = "Application key must not be empty when creating activation using recovery code")
    private String applicationKey;

    @Schema(description = "Maximum number of failures for the activation")
    @Positive(message = "Maximum failure count must be positive when creating activation using recovery code")
    private Long maxFailureCount;

    @Schema(description = "Identifier of the temporary key for encryption")
    private String temporaryKeyId;
    @Schema(description = "Ephemeral public key used in encryption")

    @NotBlank(message = "Ephemeral public key must not be empty when creating activation using recovery code")
    private String ephemeralPublicKey;

    @Schema(description = "Encrypted data used in encryption")
    @NotBlank(message = "Encrypted data must not be empty when creating activation using recovery code")
    private String encryptedData;

    @Schema(description = "Value of MAC used in encryption")
    @NotBlank(message = "Value of MAC must not be empty when creating activation using recovery code")
    private String mac;

    @Schema(description = "Activation nonce value")
    @ToString.Exclude
    private String nonce;

    @Schema(description = "Activation OTP value")
    @ToString.Exclude
    private String activationOtp;

    @Schema(description = "Cryptography protocol version")
    @NotBlank(message = "Protocol version must not be empty when creating activation using recovery code")
    private String protocolVersion;

    @Schema(description = "Timestamp value used in encryption")
    private Long timestamp;

}
