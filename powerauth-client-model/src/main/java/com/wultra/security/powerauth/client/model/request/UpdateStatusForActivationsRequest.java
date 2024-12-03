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

import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing request for bulk updating activation status.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class UpdateStatusForActivationsRequest {

    @Schema(description = "Activation identifiers")
    @NotEmpty(message = "List of activation identifiers must not be empty when updating activation status")
    private List<String> activationIds = new ArrayList<>();

    @Schema(description = "Activation status")
    @NotNull(message = "Activation status must not be empty when updating activation status")
    private ActivationStatus activationStatus;

}
