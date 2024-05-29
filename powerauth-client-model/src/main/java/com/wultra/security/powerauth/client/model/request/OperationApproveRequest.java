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

package com.wultra.security.powerauth.client.model.request;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Request object for operation approval.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class OperationApproveRequest {

    private String operationId;
    private String userId;
    private String applicationId;
    private String data;
    private SignatureType signatureType;

    @JsonSetter(nulls = Nulls.SKIP)
    private final Map<String, Object> additionalData = new LinkedHashMap<>();

    /**
     * Optional details why the status has changed. The value is more about code than free-text detail.
     */
    @Schema(description = "Optional details why the status has changed. The value is more about code than free-text detail.")
    @Size(max = 32)
    private String statusReason;

}
