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

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.ToString;

/**
 * Model class representing request for unlocking secure vault.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class VaultUnlockRequest {

    @Schema(description = "Activation identifier")
    @NotBlank(message = "Activation ID must not be empty when unlocking vault")
    private String activationId;

    @Schema(description = "Application key")
    @NotBlank(message = "Application key must not be empty when unlocking vault")
    private String applicationKey;

    @Schema(description = "Signed data")
    @NotBlank(message = "Signed data must not be empty when unlocking vault")
    private String signedData;

    @Schema(description = "Signature")
    @NotBlank(message = "Signature must not be empty when unlocking vault")
    @ToString.Exclude
    private String signature;

    @Schema(description = "Signature type")
    @NotNull(message = "Signature type must not be empty when unlocking vault")
    private SignatureType signatureType;

    @Schema(description = "Signature version")
    @NotNull(message = "Signature version must not be empty when unlocking vault")
    private String signatureVersion;

    @Schema(description = "Identifier of the temporary key for encryption")
    private String temporaryKeyId;

    @Schema(description = "Ephemeral public key used in encryption")
    @NotBlank(message = "Ephemeral public key must not be empty when unlocking vault")
    private String ephemeralPublicKey;

    @Schema(description = "Encrypted data used in encryption")
    @NotBlank(message = "Encrypted data must not be empty when unlocking vault")
    private String encryptedData;

    @Schema(description = "Value of MAC used in encryption")
    @NotBlank(message = "Value of MAC must not be empty when unlocking vault")
    private String mac;

    @Schema(description = "Activation nonce value")
    @ToString.Exclude
    private String nonce;

    @Schema(description = "Timestamp value used in encryption")
    private Long timestamp;

}
