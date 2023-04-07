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
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import lombok.Data;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Model class representing signature audit item entity.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class SignatureAuditItem {

    private long id;
    private String userId;
    private String applicationId;
    private String activationId;
    private long activationCounter;
    private String activationCtrData;
    private ActivationStatus activationStatus;
    private List<KeyValue> additionalInfo = new ArrayList<>();
    private String dataBase64;
    private String signatureVersion;
    private SignatureType signatureType;
    private String signature;
    private String note;
    private boolean valid;
    private long version;
    private Date timestampCreated;

}
