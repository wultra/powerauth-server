/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.app.server.converter;

import tools.jackson.core.JsonGenerator;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Base64;

/**
 * JSON serializer for public keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PublicKeySerializer extends ValueSerializer<PublicKey> {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    @Override
    public void serialize(PublicKey publicKey, JsonGenerator gen, SerializationContext ctx) {
        try {
            if (publicKey == null) {
                throw new IllegalArgumentException("Missing public key to serialize");
            }
            switch (publicKey.getAlgorithm()) {
                case "EC": {
                    final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                    final EllipticCurve curve = ecPublicKey.getParams().getCurve();
                    switch (curve.getField().getFieldSize()) {
                        case 256: {
                            gen.writeString(Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, publicKey)));
                            break;
                        }
                        case 384: {
                            gen.writeString(Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, publicKey)));
                            break;
                        }
                        default: throw DatabindException.from(gen, "Invalid EC curve during public key conversion");
                    }
                    break;
                }
                case "ML-DSA-65", "ML-DSA-87": {
                    gen.writeString(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                    break;
                }
                default:
                    throw DatabindException.from(gen, "Unsupported algorithm: " + publicKey.getAlgorithm());
            }
        } catch (CryptoProviderException | GenericCryptoException e) {
            throw DatabindException.from(gen, "Public key conversion failed", e);
        }
    }

}
