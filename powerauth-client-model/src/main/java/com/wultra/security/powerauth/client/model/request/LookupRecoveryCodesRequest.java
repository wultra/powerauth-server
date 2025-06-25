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

import com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus;
import com.wultra.security.powerauth.client.model.enumeration.RecoveryPukStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * Model class representing request for recovery code lookup.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class LookupRecoveryCodesRequest {

    @Schema(description = "The identifier of the user")
    private String userId;

    @Schema(description = "Activation identifier")
    private String activationId;

    @Schema(description = "The identifier of the application")
    private String applicationId;

    @Schema(description = "Recovery code status")
    private RecoveryCodeStatus recoveryCodeStatus;

    @Schema(description = "Recovery PUK status")
    private RecoveryPukStatus recoveryPukStatus;

}
