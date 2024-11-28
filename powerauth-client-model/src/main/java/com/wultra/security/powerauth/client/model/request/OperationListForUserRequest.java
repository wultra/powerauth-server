/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Request model for operation list for user.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class OperationListForUserRequest {

    @Schema(description = "The identifier of the user")
    @NotBlank(message = "User ID must not be empty when requesting operation list")
    private String userId;

    @Schema(description = "Associated application identifiers")
    @NotNull(message = "Application ID list must not be null when requesting operation list")
    @Size(min = 1, message = "Application ID list must not be empty when requesting operation list")
    private List<String> applications = new ArrayList<>();

    @Min(0)
    private Integer pageNumber;

    @Min(1)
    private Integer pageSize;

    @Schema(description = "The identifier of the activation")
    private String activationId;

}
