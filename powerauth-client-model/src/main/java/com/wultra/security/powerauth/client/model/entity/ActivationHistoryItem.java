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

import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import lombok.Data;

import java.util.Date;

/**
 * Model class representing activation history item entity.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class ActivationHistoryItem {

    private long id;
    private String activationId;
    private ActivationStatus activationStatus;
    private String eventReason;
    private String externalUserId;
    private String activationName;
    private Date timestampCreated;
    private Long version;

}
