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

package io.getlime.security.powerauth.app.server.service.exceptions;

import java.io.Serial;

/**
 * Exception thrown in case of unknown telemetry report is requested.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class TelemetryReportException extends Exception {
    @Serial
    private static final long serialVersionUID = 8770243960531807727L;

    public TelemetryReportException(String message) {
        super(message);
    }
}
