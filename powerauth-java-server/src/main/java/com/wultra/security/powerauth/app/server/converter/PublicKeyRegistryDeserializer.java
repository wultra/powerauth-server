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

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;

/**
 * JSON deserializer for public keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class PublicKeyRegistryDeserializer extends JsonDeserializer<PublicKeyRegistry> {

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new PqcDsaKeyConvertor();

    @Override
    public PublicKeyRegistry deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        final JsonNode root = jsonParser.getCodec().readTree(jsonParser);
        final PublicKeyRegistry keyRegistry = new PublicKeyRegistry();

        final JsonNode publicKeysNode = root.get("publicKeys");
        final Iterator<String> algorithmNames = publicKeysNode.fieldNames();
        while (algorithmNames.hasNext()) {
            final String algorithmName = algorithmNames.next();
            final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(algorithmName);
            final JsonNode algorithmNode = publicKeysNode.get(algorithmName);
            if (algorithmNode == null || algorithmNode.isEmpty()) {
                continue;
            }
            final Iterator<String> keyTypeNames = algorithmNode.fieldNames();
            while (keyTypeNames.hasNext()) {
                final String keyTypeName = keyTypeNames.next();
                final KeyType keyType = KeyType.valueOf(keyTypeName);
                final byte[] encodedKey = algorithmNode.get(keyTypeName).binaryValue();
                final PublicKey key = deserializePublicKey(algorithm, keyType, encodedKey);
                keyRegistry.storePublicKey(algorithm, keyType, key);
            }
        }
        return keyRegistry;
    }

    private PublicKey deserializePublicKey(SharedSecretAlgorithm algorithm, KeyType keyType, byte[] encodedKey) throws IOException {
        try {
            return switch (algorithm) {
                case EC_P256, EC_P384 -> {
                    if (keyType == KeyType.ECDSA) {
                        yield KEY_CONVERTOR_EC.convertBytesToPublicKey(getCurve(algorithm), encodedKey);
                    }
                    throw new IOException("Unsupported key type: " + keyType + " for algorithm: " + algorithm);
                }
                case EC_P384_ML_L3 -> switch (keyType) {
                    case ECDSA -> KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, encodedKey);
                    case MLDSA -> KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(encodedKey);
                };
            };
        } catch (CryptoProviderException | InvalidKeySpecException | GenericCryptoException e) {
            logger.debug(e.getMessage(), e);
            throw new IOException(e);
        }
    }

    private EcCurve getCurve(SharedSecretAlgorithm algorithm) {
        return switch (algorithm) {
            case EC_P256 -> EcCurve.P256;
            case EC_P384, EC_P384_ML_L3 -> EcCurve.P384;
        };
    }

}
