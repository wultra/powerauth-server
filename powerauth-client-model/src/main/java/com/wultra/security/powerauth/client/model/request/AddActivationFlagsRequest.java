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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing request for adding activation flags.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class AddActivationFlagsRequest {

    @Schema(description = "Activation identifier")
    @NotBlank(message = "Activation ID must not be empty when adding activation flags")
    private String activationId;

    @Schema(description = "List of activation flags")
    @NotEmpty(message = "List of activation flags must not be empty when adding activation flags")
    private List<@NotBlank String> activationFlags = new ArrayList<>();

}
