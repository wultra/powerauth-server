/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package com.wultra.security.powerauth.fido2.model.response;

import com.wultra.security.powerauth.fido2.model.enumeration.ActivationStatus;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class RegistrationResponse {

    private String userId;
    private String activationId;
    private String applicationId;
    private String credentialId;
    private String activationName;
    private ActivationStatus activationStatus;
    private Map<String, Object> extras;
    private String platform;
    private String deviceInfo;
    private String blockedReason;
    private long failedAttempts;
    private long maxFailedAttempts;
    private List<String> applicationRoles = new ArrayList<>();
    private List<String> activationFlags = new ArrayList<>();
    private byte[] publicKeyBytes;

}
