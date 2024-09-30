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

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing callback URL entity.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class CallbackUrl {

    private String id;
    private String applicationId;
    private String name;
    private String type;
    private String callbackUrl;
    private List<String> attributes = new ArrayList<>();
    private HttpAuthenticationPublic authentication = new HttpAuthenticationPublic();

    @JsonFormat(shape = JsonFormat.Shape.STRING)
    @Schema(type = "string", format = "ISO 8601 Duration", example = "P30D")
    private Duration retentionPeriod;

    @JsonFormat(shape = JsonFormat.Shape.STRING)
    @Schema(type = "string", format = "ISO 8601 Duration", example = "PT2.5S")
    private Duration initialBackoff;

    @Schema(type = "integer", example = "1")
    private Integer maxAttempts;

}
