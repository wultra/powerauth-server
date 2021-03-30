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

package com.wultra.security.powerauth.client.model.entity;

import com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus;
import lombok.Data;

import java.util.List;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class RecoveryCode {

    private long recoveryCodeId;
    private String recoveryCodeMasked;
    private String userId;
    private long applicationId;
    private String activationId;
    private RecoveryCodeStatus status;
    private List<RecoveryCodePuk> puks;

}
