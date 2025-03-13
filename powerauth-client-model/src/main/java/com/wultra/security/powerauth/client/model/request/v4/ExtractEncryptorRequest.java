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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.ToString;

/**
 * Model class representing request for AEAD encryptor initialization (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class ExtractEncryptorRequest {

    @Schema(description = "Activation identifier")
    private String activationId;

    @Schema(description = "Application key")
    @NotBlank(message = "Application key must not be empty when requesting encryptor")
    private String applicationKey;

    @Schema(description = "Identifier of the temporary key for encryption")
    @NotBlank(message = "Temporary key ID must not be empty when requesting encryptor")
    private String temporaryKeyId;

    @Schema(description = "Nonce value")
    @NotBlank(message = "Nonce must not be empty when requesting encryptor")
    @ToString.Exclude
    private String nonce;

    @Schema(description = "Cryptography protocol version")
    @NotBlank(message = "Protocol version must not be empty when requesting encryptor")
    private String protocolVersion;

    @Schema(description = "Timestamp value used in encryption")
    @NotNull(message = "Timestamp must not be null when requesting encryptor")
    @Positive(message = "Timestamp must be positive when requesting encryptor")
    private Long timestamp;

}
