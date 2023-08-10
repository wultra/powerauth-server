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

package com.wultra.security.powerauth.client.model.response;

import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing response with offline signature verification results.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class VerifyOfflineSignatureResponse {

    private boolean signatureValid;
    private ActivationStatus activationStatus;
    private String blockedReason;
    private String activationId;
    private String userId;
    private String applicationId;
    private SignatureType signatureType;
    private BigInteger remainingAttempts;
    private List<String> applicationRoles = new ArrayList<>();
    private List<String> activationFlags = new ArrayList<>();

    @Schema(description = "Optional proximity check context. Null if the context was not filled in the request.")
    private ProximityCheck proximityCheck;

    @Builder
    @Getter
    public static class ProximityCheck {
        @Schema(description = "Whether verification of TOTP was successful.")
        private boolean success;

        @Schema(description = "Optional error detail if TOTP was not successful.")
        private String errorDetail;
    }

}
