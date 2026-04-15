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

import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Converter from {@link AuthenticationCodeType} to {@link PowerAuthCodeType}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AuthenticationCodeTypeConverter {

    public static PowerAuthCodeType convert(final AuthenticationCodeType authCodeType) {
        return switch (authCodeType) {
            case POSSESSION -> PowerAuthCodeType.POSSESSION;
            case POSSESSION_KNOWLEDGE -> PowerAuthCodeType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> PowerAuthCodeType.POSSESSION_BIOMETRY;
        };
    }

    public static AuthenticationCodeType convert(final String authCodeType) {
        return AuthenticationCodeType.enumFromString(authCodeType.toUpperCase());
    }

    public static AuthenticationCodeType convert(final PowerAuthCodeType powerAuthCodeType) {
        return switch (powerAuthCodeType) {
            case POSSESSION -> AuthenticationCodeType.POSSESSION;
            case POSSESSION_KNOWLEDGE -> AuthenticationCodeType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> AuthenticationCodeType.POSSESSION_BIOMETRY;
        };
    }

}
