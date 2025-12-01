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

import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.SdkConfiguration;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.wultra.security.powerauth.app.server.service.model.ServiceError.INVALID_APPLICATION;
import static com.wultra.security.powerauth.app.server.service.model.ServiceError.INVALID_REQUEST;

/**
 * Writer for serialized PowerAuth mobile SDK configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
@AllArgsConstructor
@Service
public class SdkConfigurationSerializer {

    private static final byte SDK_CONFIGURATION_VERSION = 0x01;
    private static final byte KEY_MASTER_ECDSA_P256_PUBLIC = 0x01;
    private static final byte KEY_MASTER_ECDSA_P384_PUBLIC = 0x02;
    private static final byte KEY_MASTER_MLDSA65_PUBLIC = 0x03;
    private static final byte KEY_MASTER_MLDSA87_PUBLIC = 0x04;

    private final LocalizationProvider localizationProvider;

    /**
     * Serialize SDK configuration into a single Base-64 encoded string.
     * @param config SDK configuration.
     * @return Base-64 encoded string.
     * @throws GenericServiceException In case SDK configuration is invalid.
     */
    public String serialize(SdkConfiguration config) throws GenericServiceException {
        final String appKey = config.appKey();
        final String appSecret = config.appSecret();
        final String publicKeyP256 = config.masterPublicKeyP256();
        final String publicKeyP384 = config.masterPublicKeyP384();
        final String publicKeyMlDsa65 = config.masterPublicKeyMlDsa65();
        final String publicKeyMlDsa87 = config.masterPublicKeyMlDsa87();
        if (appKey == null || appKey.isEmpty()) {
            logger.warn("Missing parameter appKey in SDK configuration");
            throw localizationProvider.buildExceptionForCode(INVALID_APPLICATION);
        }
        if (appSecret == null || appSecret.isEmpty()) {
            logger.warn("Missing parameter appSecret in SDK configuration");
            throw localizationProvider.buildExceptionForCode(INVALID_APPLICATION);
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
        if (publicKeyMlDsa87 != null) {
            publicKeys.put(KEY_MASTER_MLDSA87_PUBLIC, publicKeyMlDsa87);
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
     * @throws GenericServiceException In case serialized SDK configuration is invalid.
     */
    public SdkConfiguration deserialize(String serialized) throws GenericServiceException {
        final byte[] serializedBytes = Base64.getDecoder().decode(serialized);
        final SdkDataReader reader = new SdkDataReader(serializedBytes);
        final Byte version = reader.readByte();
        if (version == null || version != SDK_CONFIGURATION_VERSION) {
            logger.warn("Invalid SDK configuration version: {}", version);
            throw localizationProvider.buildExceptionForCode(INVALID_REQUEST);
        }
        final byte[] appKey = reader.readData(16);
        final byte[] appSecret = reader.readData(16);
        if (appKey == null) {
            logger.warn("Missing parameter appKey in SDK configuration");
            throw localizationProvider.buildExceptionForCode(INVALID_REQUEST);
        }
        if (appSecret == null) {
            logger.warn("Missing parameter appSecret in SDK configuration");
            throw localizationProvider.buildExceptionForCode(INVALID_REQUEST);
        }
        final Map<Byte, String> publicKeys = deserializeKeys(reader);
        final String publicKeyP256 = publicKeys.get(KEY_MASTER_ECDSA_P256_PUBLIC);
        final String publicKeyP384 = publicKeys.get(KEY_MASTER_ECDSA_P384_PUBLIC);
        final String publicKeyMlDsa65 = publicKeys.get(KEY_MASTER_MLDSA65_PUBLIC);
        final String publicKeyMlDsa87 = publicKeys.get(KEY_MASTER_MLDSA87_PUBLIC);
        final String appKeyBase64 = Base64.getEncoder().encodeToString(appKey);
        final String appSecretBase64 = Base64.getEncoder().encodeToString(appSecret);
        return SdkConfiguration.builder()
                .appKey(appKeyBase64)
                .appSecret(appSecretBase64)
                .masterPublicKeyP256(publicKeyP256)
                .masterPublicKeyP384(publicKeyP384)
                .masterPublicKeyMlDsa65(publicKeyMlDsa65)
                .masterPublicKeyMlDsa87(publicKeyMlDsa87)
                .build();
    }

    /**
     * Serialize public keys using writer.
     * @param writer SDK data writer.
     * @param publicKeys Map of public key ID to public key in Base-64 format.
     */
    private void serializeKeys(SdkDataWriter writer, Map<Byte, String> publicKeys) {
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
    private Map<Byte, String> deserializeKeys(SdkDataReader reader) throws GenericServiceException {
        final Map<Byte, String> publicKeys = new LinkedHashMap<>();
        final Integer keyCount = reader.readCount();
        if (keyCount == null) {
            logger.warn("Missing key count in SDK configuration");
            throw localizationProvider.buildExceptionForCode(INVALID_REQUEST);
        }
        for (int i = 0; i < keyCount; i++) {
            final Byte keyId = reader.readByte();
            if (keyId == null) {
                logger.warn("Missing key identifier in SDK configuration");
                throw localizationProvider.buildExceptionForCode(INVALID_REQUEST);
            }
            final byte[] publicKey = reader.readData(0);
            if (publicKey == null) {
                logger.warn("Missing public key in SDK configuration");
                throw localizationProvider.buildExceptionForCode(INVALID_REQUEST);
            }
            publicKeys.put(keyId, Base64.getEncoder().encodeToString(publicKey));
        }
        return publicKeys;
    }
}