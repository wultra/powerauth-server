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

package io.getlime.security.powerauth.app.server.converter;

import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlType;

/**
 * Convertor between CallbackUrlType from client model and CallbackUrlType from database model.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
public final class CallbackUrlTypeConverter {

    public static CallbackUrlType convert(com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType src) {
        if (src == null) {
            return null;
        }

        return switch (src) {
            case ACTIVATION_STATUS_CHANGE -> CallbackUrlType.ACTIVATION_STATUS_CHANGE;
            case OPERATION_STATUS_CHANGE -> CallbackUrlType.OPERATION_STATUS_CHANGE;
        };
    }

    public static com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType convert(CallbackUrlType src) {
        if (src == null) {
            return null;
        }

        return switch (src) {
            case ACTIVATION_STATUS_CHANGE -> com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType.ACTIVATION_STATUS_CHANGE;
            case OPERATION_STATUS_CHANGE -> com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType.OPERATION_STATUS_CHANGE;
        };
    }

}
