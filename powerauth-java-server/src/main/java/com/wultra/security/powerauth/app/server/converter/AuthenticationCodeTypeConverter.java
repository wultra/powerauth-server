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

/**
 * Converter from {@link AuthenticationCodeType} to {@link PowerAuthCodeType}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
final public class AuthenticationCodeTypeConverter {

    public PowerAuthCodeType convertFrom(AuthenticationCodeType authCodeType) {
        return switch (authCodeType) {
            case POSSESSION -> PowerAuthCodeType.POSSESSION;
            case KNOWLEDGE -> PowerAuthCodeType.KNOWLEDGE;
            case BIOMETRY -> PowerAuthCodeType.BIOMETRY;
            case POSSESSION_KNOWLEDGE -> PowerAuthCodeType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> PowerAuthCodeType.POSSESSION_BIOMETRY;
            default -> PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY;
        };
    }

    public AuthenticationCodeType convertFrom(String authCodeType) {
        return AuthenticationCodeType.enumFromString(authCodeType.toUpperCase());
    }

    public AuthenticationCodeType convertTo(PowerAuthCodeType PowerAuthCodeType) {
        return switch (PowerAuthCodeType) {
            case POSSESSION -> AuthenticationCodeType.POSSESSION;
            case KNOWLEDGE -> AuthenticationCodeType.KNOWLEDGE;
            case BIOMETRY -> AuthenticationCodeType.BIOMETRY;
            case POSSESSION_KNOWLEDGE -> AuthenticationCodeType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> AuthenticationCodeType.POSSESSION_BIOMETRY;
            default -> AuthenticationCodeType.POSSESSION_KNOWLEDGE_BIOMETRY;
        };
    }

}
