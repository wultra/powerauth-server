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

package io.getlime.security.powerauth.app.server.controller.api;

import com.wultra.security.powerauth.client.model.request.TelemetryReportRequest;
import com.wultra.security.powerauth.client.model.response.TelemetryReportResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.TelemetryServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.TelemetryReportException;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller for system telemetry.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController
@RequestMapping("/rest/v3/telemetry")
@Validated
@Tag(name = "PowerAuth Telemetry Controller V3")
public class TelemetryController {

    private final TelemetryServiceBehavior telemetryServiceBehavior;

    @Autowired
    public TelemetryController(TelemetryServiceBehavior telemetryServiceBehavior) {
        this.telemetryServiceBehavior = telemetryServiceBehavior;
    }

    @PostMapping("report")
    public ObjectResponse<TelemetryReportResponse> report(@Valid @RequestBody ObjectRequest<TelemetryReportRequest> request) throws TelemetryReportException {
        final TelemetryReportRequest requestObject = request.getRequestObject();
        final String reportName = requestObject.getName();
        final Map<String, Object> parameters = requestObject.getParameters();
        final TelemetryReportResponse responseObject = telemetryServiceBehavior.report(reportName, parameters);
        return new ObjectResponse<>(responseObject);
    }


}
