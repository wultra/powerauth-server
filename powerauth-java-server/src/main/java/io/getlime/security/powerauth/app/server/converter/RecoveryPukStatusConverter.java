/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

import com.wultra.security.powerauth.client.model.enumeration.RecoveryPukStatus;

/**
 * Converter class between {@link RecoveryPukStatus} and
 * {@link io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoveryPukStatusConverter {

    /**
     * Convert recovery PUK status from entity model to web service model.
     * @param recoveryPukStatus Recovery PUK status.
     * @return Converted recovery PUK status.
     */
    public RecoveryPukStatus convertFrom(io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus recoveryPukStatus) {
        if (recoveryPukStatus == null) {
            return null;
        }
        switch (recoveryPukStatus) {
            case VALID:
                return RecoveryPukStatus.VALID;
            case USED:
                return RecoveryPukStatus.USED;
            case INVALID:
                return RecoveryPukStatus.INVALID;
        }
        return RecoveryPukStatus.INVALID;
    }

    /**
     * Convert recovery PUK status from web service model to entity model.
     * @param recoveryPukStatus Recovery PUK status.
     * @return Converted recovery PUK status.
     */
    public io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus convertTo(RecoveryPukStatus recoveryPukStatus) {
        if (recoveryPukStatus == null) {
            return null;
        }
        switch (recoveryPukStatus) {
            case VALID:
                return io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus.VALID;
            case USED:
                return io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus.USED;
            case INVALID:
                return io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus.INVALID;
        }
        return io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus.INVALID;
    }

}
