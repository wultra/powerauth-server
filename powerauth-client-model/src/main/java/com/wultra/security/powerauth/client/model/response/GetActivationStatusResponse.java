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

import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Model class representing response with activation status.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class GetActivationStatusResponse {

    private String activationId;
    private ActivationStatus activationStatus;
    private ActivationOtpValidation activationOtpValidation;
    private String blockedReason;
    private String activationName;
    private String userId;
    private String extras;
    private String platform;
    private String deviceInfo;
    private String applicationId;
    private Date timestampCreated;
    private Date timestampLastUsed;
    private Date timestampLastChange;
    @ToString.Exclude
    private String encryptedStatusBlob;
    @ToString.Exclude
    private String encryptedStatusBlobNonce;
    @ToString.Exclude
    private String activationCode;
    @ToString.Exclude
    private String activationSignature;
    @ToString.Exclude
    private String devicePublicKeyFingerprint;
    private long version;
    private List<String> activationFlags = new ArrayList<>();

}
