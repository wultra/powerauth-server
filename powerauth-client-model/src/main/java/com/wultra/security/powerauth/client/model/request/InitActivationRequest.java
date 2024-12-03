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

import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.enumeration.CommitPhase;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Model class representing request for initializing activation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class InitActivationRequest {

    private ActivationProtocol protocol = ActivationProtocol.POWERAUTH;

    @Schema(description = "The identifier of the user")
    @NotBlank(message = "User ID must not be empty when initiating activation")
    private String userId;

    @Schema(description = "The identifier of the application")
    @NotNull(message = "Application ID must not be null when initiating activation")
    private String applicationId;

    @Schema(description = "Timestamp of activation expiration")
    @Future(message = "The activation expiration timestamp must be in the future when initiating activation")
    private Date timestampActivationExpire;

    @Schema(description = "Maximum number of failures for the activation")
    @Positive(message = "Maximum failure count must be positive when initiating activation")
    private Long maxFailureCount;

    /**
     * @deprecated use {@link #activationOtp} for enabling OTP check and {@link #commitPhase} for controlling activation commit
     */
    @Schema(description = "Activation OTP validation (deprecated)")
    @Deprecated
    private ActivationOtpValidation activationOtpValidation;

    @Schema(description = "Activation commit phase")
    private CommitPhase commitPhase;

    @Schema(description = "Activation OTP value")
    @ToString.Exclude
    private String activationOtp;

    @Schema(description = "List of activation flags")
    private List<String> flags = new ArrayList<>();

}
