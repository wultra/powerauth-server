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

package com.wultra.security.powerauth.client.model.response;

import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import lombok.Data;
import lombok.ToString;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Response object for creating the operation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class OperationDetailResponse {

    private String id;
    private String userId;
    private List<String> applications;
    private String externalId;
    private String activationFlag;
    private String operationType;
    private String templateName;
    private String data;
    private Map<String, String> parameters;
    private Map<String, Object> additionalData;
    private OperationStatus status;
    private List<SignatureType> signatureType;
    private long failureCount;
    private Long maxFailureCount;
    private Date timestampCreated;
    private Date timestampExpires;
    private Date timestampFinalized;
    private String riskFlags;

    /**
     * TOTP for proximity check (if enabled) valid for the current time step.
     */
    @ToString.Exclude
    private String proximityOtp;
    private String activationId;

}
