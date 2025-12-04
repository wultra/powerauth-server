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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;

/**
 * JSON deserializer for private keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class PrivateKeyRegistryDeserializer extends JsonDeserializer<PrivateKeyRegistry> {

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    @Override
    public PrivateKeyRegistry deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        final JsonNode root = jsonParser.getCodec().readTree(jsonParser);
        if (root == null) {
            throw new IOException("Invalid JSON for private key registry");
        }

        final PrivateKeyRegistry keyRegistry = new PrivateKeyRegistry();

        final JsonNode privateKeysNode = root.get("privateKeys");
        if (privateKeysNode == null) {
            throw new IOException("Invalid JSON for private key registry");
        }
        final Iterator<String> keyTypeNames = privateKeysNode.fieldNames();
        while (keyTypeNames.hasNext()) {
            final String keyTypeName = keyTypeNames.next();
            final KeyType keyType = KeyType.valueOf(keyTypeName);
            final byte[] encodedKey = privateKeysNode.get(keyTypeName).binaryValue();
            if (encodedKey == null) {
                throw new IOException("Missing key " + keyTypeName + " in private key registry");
            }
            final PrivateKey key = deserializePrivateKey(keyType, encodedKey);
            keyRegistry.storePrivateKey(keyType, key);
        }
        return keyRegistry;
    }

    private PrivateKey deserializePrivateKey(KeyType keyType, byte[] encodedKey) throws IOException {
        try {
            return switch (keyType) {
                case ECDSA_P256 -> KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P256, encodedKey);
                case ECDSA_P384 -> KEY_CONVERTOR_EC.convertBytesToPrivateKey(EcCurve.P384, encodedKey);
                case MLDSA_65, MLDSA_87 -> KEY_CONVERTOR_PQC_DSA.convertBytesToPrivateKey(encodedKey);
            };
        } catch (CryptoProviderException | InvalidKeySpecException | GenericCryptoException e) {
            logger.debug("Key conversion failed: {}", e.getMessage(), e);
            throw new IOException("Key conversion error", e);
        }
    }

}
