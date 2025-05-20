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

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

/**
 * Converter from {@link SignatureType} to {@link PowerAuthSignatureTypes}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
final public class SignatureTypeConverter {

    public PowerAuthSignatureTypes convertFrom(SignatureType signatureType) {
        return switch (signatureType) {
            case POSSESSION -> PowerAuthSignatureTypes.POSSESSION;
            case KNOWLEDGE -> PowerAuthSignatureTypes.KNOWLEDGE;
            case BIOMETRY -> PowerAuthSignatureTypes.BIOMETRY;
            case POSSESSION_KNOWLEDGE -> PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> PowerAuthSignatureTypes.POSSESSION_BIOMETRY;
            default -> PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY;
        };
    }

    public SignatureType convertFrom(String signatureType) {
        return SignatureType.enumFromString(signatureType.toUpperCase());
    }

    public SignatureType convertTo(PowerAuthSignatureTypes powerAuthSignatureTypes) {
        return switch (powerAuthSignatureTypes) {
            case POSSESSION -> SignatureType.POSSESSION;
            case KNOWLEDGE -> SignatureType.KNOWLEDGE;
            case BIOMETRY -> SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE -> SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> SignatureType.POSSESSION_BIOMETRY;
            default -> SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        };
    }

}
