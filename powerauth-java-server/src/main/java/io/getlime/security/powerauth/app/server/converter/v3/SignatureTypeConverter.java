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

import com.wultra.security.powerauth.client.v3.SignatureType;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

/**
 * Converter from {@link SignatureType} to {@link PowerAuthSignatureTypes}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
final public class SignatureTypeConverter {

    public PowerAuthSignatureTypes convertFrom(SignatureType signatureType) {
        switch (signatureType) {
            case POSSESSION:
                return PowerAuthSignatureTypes.POSSESSION;
            case KNOWLEDGE:
                return PowerAuthSignatureTypes.KNOWLEDGE;
            case BIOMETRY:
                return PowerAuthSignatureTypes.BIOMETRY;
            case POSSESSION_KNOWLEDGE:
                return PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY:
                return PowerAuthSignatureTypes.POSSESSION_BIOMETRY;
            default:
                return PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY;
        }
    }

    public SignatureType convertFrom(String signatureType) {
        return SignatureType.fromValue(signatureType.toUpperCase());
    }

    public com.wultra.security.powerauth.client.v3.SignatureType convertFrom(com.wultra.security.powerauth.client.v2.SignatureType signatureType) {
        switch (signatureType) {
            case POSSESSION:
                return SignatureType.POSSESSION;
            case KNOWLEDGE:
                return SignatureType.KNOWLEDGE;
            case BIOMETRY:
                return SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE:
                return SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY:
                return SignatureType.POSSESSION_BIOMETRY;
            default:
                return SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }
    }

    public SignatureType convertTo(PowerAuthSignatureTypes powerAuthSignatureTypes) {
        switch (powerAuthSignatureTypes) {
            case POSSESSION:
                return SignatureType.POSSESSION;
            case KNOWLEDGE:
                return SignatureType.KNOWLEDGE;
            case BIOMETRY:
                return SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE:
                return SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY:
                return SignatureType.POSSESSION_BIOMETRY;
            default:
                return SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }
    }


}
