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
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Data;

/**
 * Model class representing request for creating recovery codes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class CreateRecoveryCodeRequest {

    @Schema(description = "The identifier of the application")
    @NotBlank(message = "Application ID must not be empty when creating recovery code")
    private String applicationId;

    @Schema(description = "The identifier of the user")
    @NotBlank(message = "User ID must not be empty when creating recovery code")
    private String userId;

    @Schema(description = "The number of PUK codes")
    @Positive(message = "The PUK count value should be positive when creating recovery code")
    @Max(value = 100, message = "The maximum PUK count of 100 was exceeded")
    private long pukCount;

}
