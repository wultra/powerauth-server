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

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Request object for operation approval.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class OperationApproveRequest {

    @Schema(description = "The identifier of the operation")
    @NotBlank(message = "Operation ID must not be empty when approving operation")
    private String operationId;

    @Schema(description = "The identifier of the user")
    @NotBlank(message = "User ID must not be empty when approving operation")
    private String userId;

    @Schema(description = "The identifier of the application")
    @NotBlank(message = "Application ID must not be empty when approving operation")
    private String applicationId;

    @Schema(description = "Operation data to approve")
    @NotBlank(message = "Data must not be empty when approving operation")
    private String data;

    @Schema(description = "Authentication code type")
    @NotNull(message = "Authentication code type must not be null when approving operation")
    private AuthenticationCodeType authenticationCodeType;

    @Schema(description = "Additional data associated with the operation")
    @JsonSetter(nulls = Nulls.SKIP)
    private final Map<String, Object> additionalData = new LinkedHashMap<>();

}
