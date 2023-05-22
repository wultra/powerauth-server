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

package io.getlime.security.powerauth.app.server.service.util;

import io.getlime.security.powerauth.app.server.service.model.SdkConfiguration;
import lombok.extern.slf4j.Slf4j;

import java.util.Base64;

/**
 * Writer for serialized PowerAuth mobile SDK configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class SdkConfigurationSerializer {

    private static final byte SDK_CONFIGURATION_VERSION = 0x01;
    private static final byte MASTER_PUBLIC_KEY_CRYPTO_V3 = 0x01;

    /**
     * Serialize SDK configuration into a single Base-64 encoded string.
     * @param config SDK configuration.
     * @return Base-64 encoded string.
     */
    public static String serialize(SdkConfiguration config) {
        final String appKeyBase64 = config.appKeyBase64();
        final String appSecretBase64 = config.appSecretBase64();
        final String masterPublicKeyBase64 = config.masterPublicKeyBase64();
        if (appKeyBase64 == null || appKeyBase64.isEmpty()) {
            throw new IllegalArgumentException("Invalid application key");
        }
        if (appSecretBase64 == null || appSecretBase64.isEmpty()) {
            throw new IllegalArgumentException("Invalid application secret");
        }
        if (masterPublicKeyBase64 == null || masterPublicKeyBase64.isEmpty()) {
            throw new IllegalArgumentException("Invalid public key");
        }
        final SdkDataWriter writer = new SdkDataWriter();
        writer.writeByte(SDK_CONFIGURATION_VERSION);
        writer.writeData(Base64.getDecoder().decode(appKeyBase64));
        writer.writeData(Base64.getDecoder().decode(appSecretBase64));
        writer.writeCount(1);
        writer.writeByte(MASTER_PUBLIC_KEY_CRYPTO_V3);
        final byte[] publicKeyBytes = Base64.getDecoder().decode(masterPublicKeyBase64);
        writer.writeData(publicKeyBytes);
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
        if (version != SDK_CONFIGURATION_VERSION) {
            // Unexpected SDK configuration version
            return null;
        }
        final byte[] appKey = reader.readData(16);
        final byte[] appSecret = reader.readData(16);
        final Integer keyCount = reader.readCount();
        if (appKey == null || appSecret == null || keyCount != 1) {
            // Unexpected data
            return null;
        }
        final Byte keyId = reader.readByte();
        if (keyId != 0x01) {
            // Invalid key ID
            return null;
        }
        final byte[] masterPublicKey = reader.readData(0);
        final String appKeyBase64 = Base64.getEncoder().encodeToString(appKey);
        final String appSecretBase64 = Base64.getEncoder().encodeToString(appSecret);
        final String masterPublicKeyBase64 = Base64.getEncoder().encodeToString(masterPublicKey);
        return new SdkConfiguration(appKeyBase64, appSecretBase64, masterPublicKeyBase64);
    }

}