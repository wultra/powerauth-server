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

import io.getlime.security.powerauth.app.server.database.model.Platform;
import io.getlime.security.powerauth.v3.PlatformType;

/**
 * Converter from {@link PlatformType} to {@link Platform}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
final public class PlatformConverter {

    public Platform convertFrom(PlatformType platform) {
        if (platform == null) {
            return Platform.UNKNOWN;
        }
        switch (platform) {
            case IOS:
                return Platform.IOS;
            case ANDROID:
                return Platform.ANDROID;
            case HW:
                return Platform.HW;
            default:
                return Platform.UNKNOWN;
        }
    }

    public PlatformType convertFrom(Platform platform) {
        if (platform == null) {
            return PlatformType.UNKNOWN;
        }
        switch (platform) {
            case IOS:
                return PlatformType.IOS;
            case ANDROID:
                return PlatformType.ANDROID;
            case HW:
                return PlatformType.HW;
            default:
                return PlatformType.UNKNOWN;
        }
    }

}
