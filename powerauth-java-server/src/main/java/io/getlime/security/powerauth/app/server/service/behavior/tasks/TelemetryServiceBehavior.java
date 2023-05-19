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

package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.client.model.response.TelemetryReportResponse;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.TelemetryReportException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for telemetry related reports.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class TelemetryServiceBehavior {

    private static final int DAYS_FOR_MAU = 30;

    // Report names
    private static final String CURRENT_MAU = "CURRENT_MAU";
    private static final String USERS_IN_PAST_DAYS = "USERS_IN_PAST_DAYS";

    // Parameter names
    private static final String PARAM_APPLICATION = "application";
    private static final String PARAM_DAYS = "days";

    // Result attribute names
    private static final String RESULT_USERS = "users";
    private static final String RESULT_APPLICATION = "application";
    private static final String RESULT_DAYS = "days";

    private final RepositoryCatalogue repositoryCatalogue;

    @Autowired
    public TelemetryServiceBehavior(RepositoryCatalogue repositoryCatalogue) {
        this.repositoryCatalogue = repositoryCatalogue;
    }

    public TelemetryReportResponse report(String reportName, Map<String, Object> parameters) throws TelemetryReportException {
        switch (reportName.toUpperCase()) {
            case CURRENT_MAU -> {
                final Map<String, Object> updatedParameters = new HashMap<>(parameters);
                updatedParameters.put(PARAM_DAYS, DAYS_FOR_MAU);
                return reportUsersInPastDays(CURRENT_MAU, updatedParameters);
            }
            case USERS_IN_PAST_DAYS -> {
                return reportUsersInPastDays(USERS_IN_PAST_DAYS, parameters);
            }
            default -> {
                throw new TelemetryReportException("Unknown report name: " + reportName);
            }
        }
    }

    /**
     * Prepare the users in past days report
     * @param reportName Provided report name.
     * @param parameters Report parameters.
     * @return Number of unique app users in specified period.
     */
    private TelemetryReportResponse reportUsersInPastDays(String reportName, Map<String, Object> parameters) throws TelemetryReportException {
        final Integer days = (Integer) parameters.get(PARAM_DAYS);
        final String applicationId = (String) parameters.get(PARAM_APPLICATION);

        // Validate report parameters are present
        if (days == null) {
            throw new TelemetryReportException("Missing parameter 'days'.");
        }
        if (days > 365) {
            throw new TelemetryReportException("The parameter 'days' must be smaller than 365. Provided: " + days);
        }
        if (applicationId == null) {
            throw new TelemetryReportException("Missing parameter 'application'.");
        }

        final Date toDate = new Date();
        final Date fromDate = Date.from(Instant.now().minus(days, ChronoUnit.DAYS));
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final long userCount = activationRepository.uniqueUserCountForApplicationBetweenDates(applicationId, fromDate, toDate);
        final TelemetryReportResponse response = new TelemetryReportResponse();
        response.setName(reportName);
        response.getReportData().put(RESULT_APPLICATION, applicationId);
        response.getReportData().put(RESULT_USERS, userCount);
        response.getReportData().put(RESULT_DAYS, days);
        return response;
    }
}
