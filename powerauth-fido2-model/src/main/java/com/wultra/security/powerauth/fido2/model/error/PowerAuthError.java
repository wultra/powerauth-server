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
package com.wultra.security.powerauth.fido2.model.error;

import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

/**
 * Class representing a PowerAuth error.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Getter
@Setter
public class PowerAuthError implements Serializable {

    @Serial
    private static final long serialVersionUID = 3172664961204150558L;

    /**
     * Error code.
     */
    private String code;

    /**
     *  Message (not localized).
     */
    private String message;

    /**
     * Localized message.
     */
    private String localizedMessage;

}
