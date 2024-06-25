/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.fido2.model.enumeration;

/**
 * Enum representing activation status.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public enum ActivationStatus {
    /**
     * Activation is created, but cannot be used as the mobile device did not send its public key,
     * and hence it could not be committed on the server side.
     */
    CREATED,

    /**
     * Activation is pending commit. The mobile device already enrolled its public key, however,
     * the commit method was not called yet.
     */
    PENDING_COMMIT,

    /**
     * Activation is ready, committed and can be used for signature verification.
     */
    ACTIVE,

    /**
     * Activation is blocked. It cannot be used for signature verification, but can be unblocked.
     */
    BLOCKED,

    /**
     * Activation is permanently removed (or non-existent). It cannot be used for signature verification,
     * and it cannot be "unblocked".
     */
    REMOVED
}
