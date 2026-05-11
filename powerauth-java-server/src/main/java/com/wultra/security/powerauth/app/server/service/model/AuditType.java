/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.service.model;

import lombok.Getter;

/**
 * This enum represents different types of audits.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Getter
public enum AuditType {

    /**
     * Audit type for signatures (V3).
     */
    SIGNATURE("signature"),

    /**
     * Audit type for authentication (V4).
     */
    AUTHENTICATION("authentication"),

    /**
     * Audit type for asymmetric signature verification (ECDSA, ML-DSA).
     */
    ASYMMETRIC_SIGNATURE("asymmetric-signature"),

    /**
     * Audit type for operations.
     */
    OPERATION("operation"),

    /**
     * Audit type for activations.
     */
    ACTIVATION("activation");

    /**
     * The code associated with each audit type.
     */
    private final String code;

    /**
     * Constructor to initialize the audit type with its code.
     *
     * @param code the code of the audit type
     */
    AuditType(final String code) {
        this.code = code;
    }

}
