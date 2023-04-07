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
package io.getlime.security.powerauth.app.server.converter;

import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;

/**
 * Converter class between {@link ActivationStatus} and
 * {@link io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ActivationStatusConverter {

    public ActivationStatus convert(io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus activationStatus) {
        switch (activationStatus) {
            case CREATED:
                return ActivationStatus.CREATED;
            case PENDING_COMMIT:
                return ActivationStatus.PENDING_COMMIT;
            case ACTIVE:
                return ActivationStatus.ACTIVE;
            case BLOCKED:
                return ActivationStatus.BLOCKED;
            case REMOVED:
                return ActivationStatus.REMOVED;
        }
        return ActivationStatus.REMOVED;
    }

    public io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus convert(ActivationStatus activationStatus) {
        switch (activationStatus) {
            case CREATED:
                return io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.CREATED;
            case PENDING_COMMIT:
                return io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.PENDING_COMMIT;
            case ACTIVE:
                return io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.ACTIVE;
            case BLOCKED:
                return io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.BLOCKED;
            case REMOVED:
                return io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.REMOVED;
        }
        return io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus.REMOVED;
    }

}
