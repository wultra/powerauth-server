/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

/**
 * Converter class between {@link com.wultra.security.powerauth.client.v3.RecoveryPukStatus} and
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
    public com.wultra.security.powerauth.client.v3.RecoveryPukStatus convertFrom(io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus recoveryPukStatus) {
        if (recoveryPukStatus == null) {
            return null;
        }
        switch (recoveryPukStatus) {
            case VALID:
                return com.wultra.security.powerauth.client.v3.RecoveryPukStatus.VALID;
            case USED:
                return com.wultra.security.powerauth.client.v3.RecoveryPukStatus.USED;
            case INVALID:
                return com.wultra.security.powerauth.client.v3.RecoveryPukStatus.INVALID;
        }
        return com.wultra.security.powerauth.client.v3.RecoveryPukStatus.INVALID;
    }

    /**
     * Convert recovery PUK status from web service model to entity model.
     * @param recoveryPukStatus Recovery PUK status.
     * @return Converted recovery PUK status.
     */
    public io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus convertTo(com.wultra.security.powerauth.client.v3.RecoveryPukStatus recoveryPukStatus) {
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
