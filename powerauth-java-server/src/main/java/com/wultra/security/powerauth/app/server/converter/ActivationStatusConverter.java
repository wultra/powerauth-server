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
package com.wultra.security.powerauth.app.server.converter;

import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;

/**
 * Converter class between {@link ActivationStatus} and
 * {@link com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ActivationStatusConverter {

    public ActivationStatus convert(com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus activationStatus) {
        return switch (activationStatus) {
            case CREATED -> ActivationStatus.CREATED;
            case PENDING_COMMIT -> ActivationStatus.PENDING_COMMIT;
            case ACTIVE -> ActivationStatus.ACTIVE;
            case BLOCKED -> ActivationStatus.BLOCKED;
            case REMOVED -> ActivationStatus.REMOVED;
        };
    }

    public com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus convert(ActivationStatus activationStatus) {
        return switch (activationStatus) {
            case CREATED -> com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus.CREATED;
            case PENDING_COMMIT -> com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus.PENDING_COMMIT;
            case ACTIVE -> com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus.ACTIVE;
            case BLOCKED -> com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus.BLOCKED;
            case REMOVED -> com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus.REMOVED;
        };
    }

}
