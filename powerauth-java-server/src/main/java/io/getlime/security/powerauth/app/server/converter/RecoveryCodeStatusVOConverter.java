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

import com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus;

/**
 * Converter class between {@link RecoveryCodeStatus} and
 * {@link io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoveryCodeStatusVOConverter {

    /**
     * Convert recovery code status from database model to web service model.
     * @param recoveryCodeStatus Recovery code status.
     * @return Converted recovery code status.
     */
    public RecoveryCodeStatus convertFrom(io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus recoveryCodeStatus) {
        if (recoveryCodeStatus == null) {
            return null;
        }
        switch (recoveryCodeStatus) {
            case CREATED:
                return RecoveryCodeStatus.CREATED;
            case ACTIVE:
                return RecoveryCodeStatus.ACTIVE;
            case BLOCKED:
                return RecoveryCodeStatus.BLOCKED;
            case REVOKED:
                return RecoveryCodeStatus.REVOKED;
        }
        return RecoveryCodeStatus.REVOKED;
    }

    /**
     * Convert recovery code status from web service model to database model.
     * @param recoveryCodeStatus Recovery code status.
     * @return Converted recovery code status.
     */
    public io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus convertTo(RecoveryCodeStatus recoveryCodeStatus) {
        if (recoveryCodeStatus == null) {
            return null;
        }
        switch (recoveryCodeStatus) {
            case CREATED:
                return io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.CREATED;
            case ACTIVE:
                return io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.ACTIVE;
            case BLOCKED:
                return io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.BLOCKED;
            case REVOKED:
                return io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.REVOKED;
        }
        return io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.REVOKED;
    }

}
