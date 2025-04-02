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
 *
 */

package com.wultra.security.powerauth.app.server.service.util;

import com.wultra.security.powerauth.app.server.service.model.SdkConfiguration;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Writer for serialized PowerAuth mobile SDK configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class SdkConfigurationSerializer {

    private static final byte SDK_CONFIGURATION_VERSION = 0x01;
    private static final byte KEY_MASTER_ECDSA_P256_PUBLIC = 0x01;
    private static final byte KEY_MASTER_ECDSA_P384_PUBLIC = 0x02;
    private static final byte KEY_MASTER_MLDSA65_PUBLIC = 0x03;

    /**
     * Serialize SDK configuration into a single Base-64 encoded string.
     * @param config SDK configuration.
     * @return Base-64 encoded string.
     */
    public static String serialize(SdkConfiguration config) {
        final String appKey = config.appKey();
        final String appSecret = config.appSecret();
        final String publicKeyP256 = config.masterPublicKeyP256();
        final String publicKeyP384 = config.masterPublicKeyP384();
        final String publicKeyMlDsa65 = config.masterPublicKeyMlDsa65();
        if (appKey == null || appKey.isEmpty()) {
            throw new IllegalArgumentException("Invalid application key");
        }
        if (appSecret == null || appSecret.isEmpty()) {
            throw new IllegalArgumentException("Invalid application secret");
        }
        final Map<Byte, String> publicKeys = new LinkedHashMap<>();
        if (publicKeyP256 != null) {
            publicKeys.put(KEY_MASTER_ECDSA_P256_PUBLIC, publicKeyP256);
        }
        if (publicKeyP384 != null) {
            publicKeys.put(KEY_MASTER_ECDSA_P384_PUBLIC, publicKeyP384);
        }
        if (publicKeyMlDsa65 != null) {
            publicKeys.put(KEY_MASTER_MLDSA65_PUBLIC, publicKeyMlDsa65);
        }
        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("Missing public keys");
        }
        final SdkDataWriter writer = new SdkDataWriter();
        writer.writeByte(SDK_CONFIGURATION_VERSION);
        writer.writeData(Base64.getDecoder().decode(appKey));
        writer.writeData(Base64.getDecoder().decode(appSecret));
        serializeKeys(writer, publicKeys);
        return Base64.getEncoder().encodeToString(writer.getSerializedData());
    }



    /**
     * Deserialize SDK configuration from a Base-64 encoded string.
     * @param serialized Serialized SDK configuration.
     * @return SDK configuration.
     */
    public static SdkConfiguration deserialize(String serialized) {
        final byte[] serializedBytes = Base64.getDecoder().decode(serialized);
        final SdkDataReader reader = new SdkDataReader(serializedBytes);
        final Byte version = reader.readByte();
        if (version == null || version != SDK_CONFIGURATION_VERSION) {
            logger.warn("Unexpected SDK configuration version: {}", version);
            return null;
        }
        final byte[] appKey = reader.readData(16);
        final byte[] appSecret = reader.readData(16);
        if (appKey == null || appSecret == null) {
            // Unexpected data
            return null;
        }
        final Map<Byte, String> publicKeys = deserializeKeys(reader);
        final String publicKeyP256 = publicKeys.get(KEY_MASTER_ECDSA_P256_PUBLIC);
        final String publicKeyP384 = publicKeys.get(KEY_MASTER_ECDSA_P384_PUBLIC);
        final String publicKeyMlDsa65 = publicKeys.get(KEY_MASTER_MLDSA65_PUBLIC);
        final String appKeyBase64 = Base64.getEncoder().encodeToString(appKey);
        final String appSecretBase64 = Base64.getEncoder().encodeToString(appSecret);
        return new SdkConfiguration(appKeyBase64, appSecretBase64, publicKeyP256, publicKeyP384, publicKeyMlDsa65);
    }

    /**
     * Serialize public keys using writer.
     * @param writer SDK data writer.
     * @param publicKeys Map of public key ID to public key in Base-64 format.
     */
    private static void serializeKeys(SdkDataWriter writer, Map<Byte, String> publicKeys) {
        writer.writeCount(publicKeys.size());
        for (Map.Entry<Byte, String> key : publicKeys.entrySet()) {
            writer.writeByte(key.getKey());
            final byte[] publicKeyBytes = Base64.getDecoder().decode(key.getValue());
            writer.writeData(publicKeyBytes);
        }
    }

    /**
     * Deserialize public keys using reader.
     * @param reader SDK data reader.
     * @return Map of public key ID to public key in Base-64 format.
     */
    private static Map<Byte, String> deserializeKeys(SdkDataReader reader) {
        final Map<Byte, String> publicKeys = new LinkedHashMap<>();
        final Integer keyCount = reader.readCount();
        for (int i = 0; i < keyCount; i++) {
            final Byte keyId = reader.readByte();
            final byte[] publicKey = reader.readData(0);
            publicKeys.put(keyId, Base64.getEncoder().encodeToString(publicKey));
        }
        return publicKeys;
    }
}