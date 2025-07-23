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
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.ToString;

import java.util.Date;

/**
 * Model class representing request for creating activation (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class CreateActivationRequest {

    @Schema(description = "The identifier of the user")
    @NotBlank(message = "User ID must not be empty when creating activation")
    private String userId;

    @Schema(description = "Timestamp of activation expiration")
    @Future(message = "The activation expiration timestamp must be in the future when creating activation")
    private Date timestampActivationExpire;

    @Schema(description = "Maximum number of failures for the activation")
    @Positive(message = "Maximum failure count must be positive when creating activation")
    private Long maxFailureCount;

    @Schema(description = "Application key")
    @NotBlank(message = "Application key must not be empty when creating activation")
    private String applicationKey;

    @Schema(description = "Identifier of the temporary key for encryption")
    @NotBlank(message = "Temporary key ID must not be empty when creating activation")
    private String temporaryKeyId;

    @Schema(description = "Encrypted data")
    @NotBlank(message = "Encrypted data must not be empty when creating activation")
    private String encryptedData;

    @Schema(description = "Nonce value")
    @NotBlank(message = "Nonce must not be empty when creating activation")
    @ToString.Exclude
    private String nonce;

    @Schema(description = "Activation OTP value")
    @ToString.Exclude
    private String activationOtp;

    @Schema(description = "Cryptography protocol version")
    @NotBlank(message = "Protocol version must not be empty when creating activation")
    private String protocolVersion;

    @Schema(description = "Timestamp value used in encryption")
    @NotNull(message = "Timestamp must not be null when creating activation")
    @Positive(message = "Timestamp must be positive when creating activation")
    private Long timestamp;

}
