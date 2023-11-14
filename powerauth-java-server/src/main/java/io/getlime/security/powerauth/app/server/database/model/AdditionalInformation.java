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

    public static class Key {
        
        /**
         * Key describing reasons for blocked activation.
         */
        public static final String BLOCKED_REASON = "BLOCKED_REASON";

        /**
         * Key describing reasons for vault unlock.
         */
        public static final String VAULT_UNLOCKED_REASON = "VAULT_UNLOCKED_REASON";

        /**
         * Key indicating if biometry is allowed for offline verifications.
         */
        public static final String BIOMETRY_ALLOWED = "BIOMETRY_ALLOWED";

    }

    public static class Reason {

        /**
         * Logged when activation was blocked because of too many failed authentication attempts.
         */
        public static final String BLOCKED_REASON_MAX_FAILED_ATTEMPTS = "MAX_FAILED_ATTEMPTS";

        /**
         * Logged when activation was blocked for any unspecified reason.
         */
        public static final String BLOCKED_REASON_NOT_SPECIFIED = "NOT_SPECIFIED";

        /**
         * Logged when vault unlock was requested with an unspecified reason.
         */
        public static final String VAULT_UNLOCKED_REASON_NOT_SPECIFIED = "NOT_SPECIFIED";

        /**
         * Logged when activation OTP validation fails, but there are still remaining attempts to validate the OTP.
         */
        public static final String ACTIVATION_OTP_FAILED_ATTEMPT = "OTP_FAILED_ATTEMPT";

        /**
         * Logged when activation OTP validation fails for the last time and activation is removed.
         */
        public static final String ACTIVATION_OTP_MAX_FAILED_ATTEMPTS = "OTP_MAX_FAILED_ATTEMPTS";

        /**
         * Logged when the OTP is updated.
         */
        public static final String ACTIVATION_OTP_VALUE_UPDATE = "OTP_VALUE_UPDATE";

        /**
         * Logged during upgrade commit (version changes to a newer one).
         */
        public static final String ACTIVATION_VERSION_CHANGED = "ACTIVATION_VERSION_CHANGED";

        /**
         * Logged when the activation name has been updated.
         */
        public static final String ACTIVATION_NAME_UPDATED = "ACTIVATION_NAME_UPDATED";

    }

    private AdditionalInformation() {
        throw new IllegalStateException("Should not be instantiated");
    }
}
