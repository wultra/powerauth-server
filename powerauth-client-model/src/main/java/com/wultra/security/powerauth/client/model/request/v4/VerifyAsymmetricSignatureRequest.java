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
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureFormat;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.ToString;

/**
 * Model class representing request for asymmetric signature verification (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class VerifyAsymmetricSignatureRequest {

    @Schema(description = "Activation identifier")
    @NotBlank(message = "Activation ID must not be empty when verifying signature")
    private String activationId;

    @Schema(description = "Signed data")
    @NotNull(message = "Data must not be null when verifying signature")
    private String data;

    @Schema(description = "Signature")
    @NotBlank(message = "Signature must not be empty when verifying signature")
    @Base64Encoded(message = "Signature must be a valid Base-64 encoded string")
    @ToString.Exclude
    private String signature;

    @Schema(description = "Signature type")
    @NotNull
    private AsymmetricSignatureType signatureType = AsymmetricSignatureType.ECDSA;

    @Schema(description = "Signature format")
    private AsymmetricSignatureFormat signatureFormat = AsymmetricSignatureFormat.DER;

}
