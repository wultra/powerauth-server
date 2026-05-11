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

import com.fasterxml.jackson.databind.SerializerProvider;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * JSON serializer for private keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PrivateKeySerializer extends ValueSerializer<PrivateKey> {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    @Override
    public void serialize(PrivateKey privateKey, JsonGenerator gen, SerializationContext ctx) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Missing private key to serialize");
        }
        switch (privateKey.getAlgorithm()) {
            case "EC": {
                try {
                    gen.writeString(Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPrivateKeyToBytes(privateKey)));
                } catch (GenericCryptoException e) {
                    throw DatabindException.from(gen, "Private key conversion failed", e);
                }
                break;
            }
            case "ML-DSA-65", "ML-DSA-87": {
                gen.writeString(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
                break;
            }
            default:
                throw DatabindException.from(gen, "Unsupported algorithm: " + privateKey.getAlgorithm());
        }
    }

}
