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

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Request to update an operation template with provided ID.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class OperationTemplateUpdateRequest {

    @Schema(description = "Operation template identifier")
    @NotNull(message = "Operation template identifier must not be empty when updating operation template")
    private Long id;

    @Schema(description = "The type of the operation that is created based on the template")
    @NotBlank(message = "Operation type must not be empty when updating operation template")
    private String operationType;

    @Schema(description = "Template for the operation data")
    @NotBlank(message = "Operation template data must not be empty when updating operation template")
    private String dataTemplate;

    @Schema(description = "Allowed signature types")
    @NotEmpty(message = "Template signature types must contain at least one value")
    @JsonSetter(nulls = Nulls.SKIP)
    private final List<@NotBlank SignatureType> signatureType = new ArrayList<>();

    @Schema(description = "How many failed attempts should be allowed for the operation")
    @NotNull(message = "Template expiration value must not be null when updating operation template")
    @Positive(message = "Template maximum allowed failure count must be greater than zero")
    private Long maxFailureCount;

    @Schema(description = "Operation expiration period in seconds")
    @NotNull(message = "Template expiration value must not be null when updating operation template")
    @Positive(message = "Template expiration value must be greater than zero")
    private Long expiration;

    @Schema(description = "Risk flags for offline QR code, uppercase letters without separator, e.g. 'XFC'")
    private String riskFlags;

    @Schema(description = "Whether proximity check is enabled and TOTP seed should be generated")
    private boolean proximityCheckEnabled;

}
