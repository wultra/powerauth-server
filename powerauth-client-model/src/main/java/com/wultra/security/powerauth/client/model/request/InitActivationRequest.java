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
    private String userId;
    private String applicationId;
    private Date timestampActivationExpire;
    private Long maxFailureCount;
    private ActivationOtpValidation activationOtpValidation;
    @ToString.Exclude
    private String activationOtp;
    private List<String> flags = new ArrayList<>();

}
