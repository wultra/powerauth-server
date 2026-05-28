/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.client.model.response.v4;

import com.fasterxml.jackson.annotation.JsonRawValue;
import com.wultra.security.powerauth.client.model.enumeration.*;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.ToString;

import java.util.*;

/**
 * Model class representing response with activation status (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class GetActivationStatusResponse {

    private String activationId;
    private ActivationStatus activationStatus;
    @Deprecated
    private ActivationOtpValidation activationOtpValidation;
    private CommitPhase commitPhase;
    private String blockedReason;
    private boolean confirmationPending;
    private String activationName;
    private String userId;

    @Schema(description = "Any custom attributes set through SDK")
    private String extras;
    private ActivationProtocol protocol;
    private String externalId;
    private String platform;
    private String deviceInfo;
    private String applicationId;
    private Long failedAttempts;
    private Long maxFailedAttempts;
    private Date timestampCreated;
    private Date timestampLastUsed;
    private Date timestampLastChange;
    @Schema(description = "Timestamp after which a temporary activation block is expired. Null when no temporary block is in effect.")
    private Date timestampBlockExpire;
    @ToString.Exclude
    private String statusBlob;
    @ToString.Exclude
    private String activationCode;
    @ToString.Exclude
    @Deprecated
    private String activationSignature;
    @ToString.Exclude
    private Map<String, String> activationSignatures = new LinkedHashMap<>();
    @ToString.Exclude
    private String devicePublicKeyFingerprint;
    private long version;
    private List<String> activationFlags = new ArrayList<>();
    private List<String> applicationRoles = new ArrayList<>();

    @Schema(description = "The activation's custom attributes set through a private API in a free JSON structure.", example = "{\"jti\":\"unique_value\"}")
    @JsonRawValue
    private Object additionalData;

    @Schema(description = "The parent activation ID. Mandatory when `transferType` is present.")
    private String parentActivationId;

    @Schema(description = "The activation transfer type. Mandatory when `parentActivationId` is present.")
    private ActivationTransferType transferType;
}
