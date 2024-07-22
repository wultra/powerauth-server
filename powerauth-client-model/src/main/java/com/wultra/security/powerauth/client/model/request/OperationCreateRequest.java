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
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.*;

/**
 * Request method for creating a new operation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class OperationCreateRequest {

    @Schema(description = "The identifier of the user", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String userId;

    @Schema(description = "List of associated applications", requiredMode = Schema.RequiredMode.REQUIRED)
    private List<String> applications = new ArrayList<>();

    @Schema(description = "Activation flag associated with the operation", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String activationFlag;

    @Schema(description = "Name of the template used for creating the operation", requiredMode = Schema.RequiredMode.REQUIRED)
    private String templateName;

    @Schema(description = "Timestamp of when the operation will expire, overrides expiration period from operation template", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Date timestampExpires;

    @Schema(description = "External identifier of the operation, i.e., ID from transaction system", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String externalId;

    @Schema(description = "Parameters of the operation, will be filled to the operation data", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    @JsonSetter(nulls = Nulls.SKIP)
    private final Map<String, String> parameters = new LinkedHashMap<>();

    @Schema(description = "Additional data associated with the operation to initialize the operation context", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    @JsonSetter(nulls = Nulls.SKIP)
    private Map<String, Object> additionalData = new LinkedHashMap<>();

    @Schema(description = "Whether proximity check should be used, overrides configuration from operation template", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Boolean proximityCheckEnabled;

    @Schema(description = "Activation ID. It is possible to specify a single device (otherwise all user's activations are taken into account).", requiredMode = Schema.RequiredMode.NOT_REQUIRED, maxLength = 37)
    private String activationId;

}
