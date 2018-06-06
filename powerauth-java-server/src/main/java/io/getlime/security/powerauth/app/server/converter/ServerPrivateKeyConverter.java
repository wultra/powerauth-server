/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Lime - HighTech Solutions s.r.o.
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

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.KeyEncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.jboss.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Converter for server private key which handles key encryption and decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@lime-company.eu
 */
@Component
public class ServerPrivateKeyConverter {

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final LocalizationProvider localizationProvider;

    // Utility classes for crypto
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final AESEncryptionUtils aesEncryptionUtils = new AESEncryptionUtils();
    private final CryptoProviderUtil keyConversionUtilities = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    @Autowired
    public ServerPrivateKeyConverter(PowerAuthServiceConfiguration powerAuthServiceConfiguration, LocalizationProvider localizationProvider) {
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.localizationProvider = localizationProvider;
    }

    /**
     * Convert server private key from composite database value to Base64-encoded string value.
     * @param keyEncryptionMode Encryption mode of value stored in database.
     * @param serverPrivateKeyBase64 Base64-encoded value of server private key, encrypted if specified by encryption mode.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Decrypted Base64-encoded server private key.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public String fromDBValue(KeyEncryptionMode keyEncryptionMode, String serverPrivateKeyBase64, String userId, String activationId) throws GenericServiceException {
        if (keyEncryptionMode == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.UNSUPPORTED_ENCRYPTION_MODE);
        }

        switch (keyEncryptionMode) {

            case NO_ENCRYPTION:
                return serverPrivateKeyBase64;

            case AES_HMAC:
                String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

                // In case master DB encryption key does not exist, do not encrypt the server private key
                if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
                    throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_MASTER_DB_ENCRYPTION_KEY);
                }

                try {
                    // Convert master DB encryption key
                    SecretKey masterDbEncryptionKey = keyConversionUtilities.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(masterDbEncryptionKeyBase64));

                    // Derive secret key from master DB encryption key, userId and activationId
                    SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, userId, activationId);

                    // Base64-decode server private key
                    byte[] serverPrivateKey = BaseEncoding.base64().decode(serverPrivateKeyBase64);

                    // Check that the length of the byte array is sufficient to avoid AIOOBE on the next calls
                    if (serverPrivateKey == null || serverPrivateKey.length < 16) {
                        Logger.getLogger(ServerPrivateKeyConverter.class.getName()).error("Invalid encrypted private key format - the byte array is too short.");
                        throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
                    }

                    // IV is present in first 16 bytes
                    byte[] iv = Arrays.copyOfRange(serverPrivateKey, 0, 16);

                    // Encrypted serverPrivateKey is present after IV
                    byte[] encryptedServerPrivateKey = Arrays.copyOfRange(serverPrivateKey, 16, serverPrivateKey.length);

                    // Decrypt serverPrivateKey
                    byte[] decryptedServerPrivateKey = aesEncryptionUtils.decrypt(encryptedServerPrivateKey, iv, secretKey);

                    // Base64-encode decrypted serverPrivateKey
                    return BaseEncoding.base64().encode(decryptedServerPrivateKey);

                } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | IllegalArgumentException ex) {
                    Logger.getLogger(ServerPrivateKeyConverter.class.getName()).error(ex.getMessage(), ex);
                    throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
                }

            default:
                Logger.getLogger(ServerPrivateKeyConverter.class.getName()).error("Unknown encryption mode provided: " + keyEncryptionMode.getValue());
                throw localizationProvider.buildExceptionForCode(ServiceError.UNSUPPORTED_ENCRYPTION_MODE);
        }
    }

    /**
     * Convert server private key to composite database value. Server private key is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * @param serverPrivateKey Server private key.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Server private key as composite database value.
     * @throws GenericServiceException Thrown when server private key encryption fails.
     */
    public ServerPrivateKey toDBValue(byte[] serverPrivateKey, String userId, String activationId) throws GenericServiceException {
        String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

        // In case master DB encryption key does not exist, do not encrypt the server private key
        if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
            return new ServerPrivateKey(KeyEncryptionMode.NO_ENCRYPTION, BaseEncoding.base64().encode(serverPrivateKey));
        }

        try {
            // Convert master DB encryption key
            SecretKey masterDbEncryptionKey = keyConversionUtilities.convertBytesToSharedSecretKey(BaseEncoding.base64().decode(masterDbEncryptionKeyBase64));

            // Derive secret key from master DB encryption key, userId and activationId
            SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, userId, activationId);

            // Generate random IV
            byte[] iv = keyGenerator.generateRandomBytes(16);

            // Encrypt serverPrivateKey using secretKey with generated IV
            byte[] encrypted = aesEncryptionUtils.encrypt(serverPrivateKey, iv, secretKey);

            // Generate output bytes as encrypted + IV
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(iv);
            baos.write(encrypted);
            byte[] record = baos.toByteArray();

            // Base64-encode output and create ServerPrivateKey instance
            String encryptedKeyBase64 = BaseEncoding.base64().encode(record);

            // Return encrypted record including encryption mode
            return new ServerPrivateKey(KeyEncryptionMode.AES_HMAC, encryptedKeyBase64);

        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IllegalArgumentException | IOException ex) {
            Logger.getLogger(ServerPrivateKeyConverter.class.getName()).error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        }
    }

    /**
     * Derive secret key from master DB encryption key, user ID and activation ID.<br/>
     * <br/>
     * See: https://github.com/lime-company/powerauth-server/wiki/Encrypting-Records-in-Database
     *
     * @param masterDbEncryptionKey Master DB encryption key.
     * @param userId User ID.
     * @param activationId Activation ID.
     * @return Derived secret key.
     */
    private SecretKey deriveSecretKey(SecretKey masterDbEncryptionKey, String userId, String activationId) {
        // Use concatenated user ID and activation ID bytes as index for KDF_INTERNAL
        byte[] index = (userId + "&" + activationId).getBytes();

        // Derive secretKey from master DB encryption key using KDF_INTERNAL with constructed index
        return keyGenerator.deriveSecretKeyHmac(masterDbEncryptionKey, index);
    }


}
