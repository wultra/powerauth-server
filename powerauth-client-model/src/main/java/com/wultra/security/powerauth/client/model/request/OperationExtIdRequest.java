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
import jakarta.validation.constraints.*;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Request for operations identified by an external ID.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class OperationExtIdRequest {

    @Schema(description = "External identifier of the operation", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "External ID must not be empty when requesting operation lookup by external ID")
    private String externalId;

    @Schema(description = "Associated application identifiers", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull(message = "Application ID list must not be null when requesting operation lookup by external ID")
    @Size(min = 1, message = "Application ID list must not be empty when requesting operation lookup by external ID")
    private List<String> applications = new ArrayList<>();

    @Min(0)
    private Integer pageNumber;

    @Min(1)
    private Integer pageSize;

}
