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

package com.wultra.security.powerauth.fido2.model.request;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Request for obtaining assertion challenge.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class AssertionChallengeRequest {

    private String userId;
    @NotEmpty
    private List<@NotBlank String> applicationIds;
    private String externalId;

    @Schema(description = "Operation which the assertion should be associated with. If `null`, a new operation is created.")
    private String operationId;

    @NotBlank
    private String templateName;
    @JsonSetter(nulls = Nulls.SKIP)
    private Map<String, String> parameters = new HashMap<>();

}
