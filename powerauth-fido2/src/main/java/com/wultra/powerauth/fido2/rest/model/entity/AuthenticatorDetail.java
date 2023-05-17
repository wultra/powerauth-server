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

package com.wultra.powerauth.fido2.rest.model.entity;

import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import lombok.Data;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Information about a registered authenticator.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class AuthenticatorDetail {

    private String userId;
    private String activationId;
    private String applicationId;
    private String activationName;
    private String externalId;
    private ActivationStatus activationStatus;
    private String extras;
    private String platform;
    private String deviceInfo;
    private String blockedReason;
    private long failedAttempts;
    private long maxFailedAttempts;
    private List<String> applicationRoles = new ArrayList<>();
    private List<String> activationFlags = new ArrayList<>();
    private byte[] publicKeyBytes;

}
