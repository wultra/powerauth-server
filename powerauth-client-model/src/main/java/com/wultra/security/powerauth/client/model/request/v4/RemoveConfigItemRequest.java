/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.client.model.request.v4;

import com.wultra.security.powerauth.client.model.enumeration.ConfigScope;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * Model class representing a request to remove a single configuration item.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class RemoveConfigItemRequest {

    @Schema(description = "Application identifier")
    @NotBlank(message = "Application ID must not be empty when removing a configuration item")
    private String applicationId;

    @Schema(description = "Activation identifier")
    private String activationId;

    @Schema(description = "Configuration scope (APPLICATION or ACTIVATION)")
    @NotNull(message = "The configuration scope must be set when removing a configuration item")
    private ConfigScope scope;

    @Schema(description = "Configuration key")
    @NotBlank(message = "The configuration key must not be empty when removing a configuration item")
    @Pattern(regexp = "^[a-zA-Z0-9_.-]{1,255}$", message = "The configuration key has an invalid format")
    private String key;

}
