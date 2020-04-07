/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.database.model;

/**
 * Constants for additional information related to activations and signature audit records.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class AdditionalInformation {

    public static final String BLOCKED_REASON = "BLOCKED_REASON";
    public static final String VAULT_UNLOCKED_REASON = "VAULT_UNLOCKED_REASON";
    public static final String BLOCKED_REASON_MAX_FAILED_ATTEMPTS = "MAX_FAILED_ATTEMPTS";
    public static final String BLOCKED_REASON_NOT_SPECIFIED = "NOT_SPECIFIED";
    public static final String VAULT_UNLOCKED_REASON_NOT_SPECIFIED = "NOT_SPECIFIED";
    public static final String BIOMETRY_ALLOWED = "BIOMETRY_ALLOWED";
    public static final String ACTIVATION_OTP_FAILED_ATTEMPT = "OTP_FAILED_ATTEMPT";
    public static final String ACTIVATION_OTP_MAX_FAILED_ATTEMPTS = "OTP_MAX_FAILED_ATTEMPTS";
    public static final String ACTIVATION_OTP_VALUE_UPDATE = "OTP_VALUE_UPDATE";
}
