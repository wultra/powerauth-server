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

import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Converter from {@link SignatureType} to {@link PowerAuthCodeType}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SignatureTypeConverter {

    public static PowerAuthCodeType convert(final SignatureType signatureType) {
        return switch (signatureType) {
            case POSSESSION -> PowerAuthCodeType.POSSESSION;
            case POSSESSION_KNOWLEDGE -> PowerAuthCodeType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> PowerAuthCodeType.POSSESSION_BIOMETRY;
        };
    }

    public static SignatureType convert(final String signatureType) {
        return SignatureType.enumFromString(signatureType.toUpperCase());
    }

    public static SignatureType convert(final PowerAuthCodeType powerAuthCodeType) {
        return switch (powerAuthCodeType) {
            case POSSESSION -> SignatureType.POSSESSION;
            case POSSESSION_KNOWLEDGE -> SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> SignatureType.POSSESSION_BIOMETRY;
        };
    }

}
