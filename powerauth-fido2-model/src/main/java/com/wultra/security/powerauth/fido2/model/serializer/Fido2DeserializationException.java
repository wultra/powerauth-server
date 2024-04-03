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

package com.wultra.security.powerauth.fido2.model.serializer;

import java.io.IOException;
import java.io.Serial;

/**
 * Exception related to FIDO2 deserialization issues.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Fido2DeserializationException extends IOException {

    @Serial
    private static final long serialVersionUID = 1835532378587759773L;

    /**
     * Exception constructor with message.
     * @param message Exception message.
     */
    public Fido2DeserializationException(String message) {
        super(message);
    }

    /**
     * Exception constructor with message and cause.
     * @param message Exception message.
     * @param cause Exception cause.
     */
    public Fido2DeserializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
