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

import tools.jackson.core.JsonParser;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

/**
 * JSON deserializer for public keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class PublicKeyRegistryDeserializer extends ValueDeserializer<PublicKeyRegistry> {

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    @Override
    public PublicKeyRegistry deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) {
        final JsonNode root = jsonParser.readValueAsTree();
        if (root == null) {
            throw DatabindException.from(jsonParser, "Invalid JSON for public key registry");
        }

        final PublicKeyRegistry keyRegistry = new PublicKeyRegistry();

        final JsonNode publicKeysNode = root.get("publicKeys");
        if (publicKeysNode == null) {
            throw DatabindException.from(jsonParser, "Invalid JSON for public key registry");
        }

        for (Map.Entry<String, JsonNode> entry : publicKeysNode.properties()) {
            final String keyTypeName = entry.getKey();
            final KeyType keyType = KeyType.valueOf(keyTypeName);
            final byte[] encodedKey = entry.getValue().binaryValue();
            if (encodedKey == null) {
                throw DatabindException.from(jsonParser, keyTypeName + " is missing in public key registry");
            }
            final PublicKey key = deserializePublicKey(jsonParser, keyType, encodedKey);
            keyRegistry.storePublicKey(keyType, key);
        }
        return keyRegistry;
    }

    private PublicKey deserializePublicKey(JsonParser jsonParser, KeyType keyType, byte[] encodedKey) {
        try {
            return switch (keyType) {
                case ECDSA_P256 -> KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P256, encodedKey);
                case ECDSA_P384 -> KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, encodedKey);
                case MLDSA_65, MLDSA_87 -> KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(encodedKey);
            };
        } catch (CryptoProviderException | InvalidKeySpecException | GenericCryptoException e) {
            logger.debug(e.getMessage(), e);
            throw DatabindException.from(jsonParser, "Failed to deserialize public key " + keyType + ": " + e.getMessage());
        }
    }

}
