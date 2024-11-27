/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
import lombok.Data;

/**
 * Request for operation claim.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class OperationClaimRequest  {

    /**
     * Operation identifier.
     */
    @Schema(description = "The identifier of the operation", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Operation ID must not be empty when requesting operation claim")
    private String operationId;

    /**
     * User identifier of the user who is claiming the operation.
     */
    @Schema(description = "The identifier of the user", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "User ID must not be empty when requesting operation claim")
    private String userId;

}
