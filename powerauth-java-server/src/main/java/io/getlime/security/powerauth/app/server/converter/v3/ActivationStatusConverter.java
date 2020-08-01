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
package io.getlime.security.powerauth.app.server.converter.v3;

import com.wultra.security.powerauth.client.v3.ActivationStatus;

/**
 * Converter class between {@link com.wultra.security.powerauth.client.v3.ActivationStatus} and
 * {@link io.getlime.security.powerauth.app.server.database.model.ActivationStatus}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ActivationStatusConverter {

    public com.wultra.security.powerauth.client.v3.ActivationStatus convert(io.getlime.security.powerauth.app.server.database.model.ActivationStatus activationStatus) {
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

    public io.getlime.security.powerauth.app.server.database.model.ActivationStatus convert(com.wultra.security.powerauth.client.v3.ActivationStatus activationStatus) {
        switch (activationStatus) {
            case CREATED:
                return io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED;
            case PENDING_COMMIT:
                return io.getlime.security.powerauth.app.server.database.model.ActivationStatus.PENDING_COMMIT;
            case ACTIVE:
                return io.getlime.security.powerauth.app.server.database.model.ActivationStatus.ACTIVE;
            case BLOCKED:
                return io.getlime.security.powerauth.app.server.database.model.ActivationStatus.BLOCKED;
            case REMOVED:
                return io.getlime.security.powerauth.app.server.database.model.ActivationStatus.REMOVED;
        }
        return io.getlime.security.powerauth.app.server.database.model.ActivationStatus.REMOVED;
    }

}
