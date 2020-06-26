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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v2;

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.v2.VaultUnlockResponse;
import io.getlime.security.powerauth.app.server.converter.v2.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Behavior class implementing the vault unlock related processes. The class separates the
 * logic from the main service class.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component("vaultUnlockServiceBehaviorV2")
public class VaultUnlockServiceBehavior {

    private final ActivationRepository powerAuthRepository;
    private final LocalizationProvider localizationProvider;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(VaultUnlockServiceBehavior.class);

    @Autowired
    public VaultUnlockServiceBehavior(ActivationRepository powerAuthRepository, LocalizationProvider localizationProvider) {
        this.powerAuthRepository = powerAuthRepository;
        this.localizationProvider = localizationProvider;
    }

    private final PowerAuthServerVault powerAuthServerVault = new PowerAuthServerVault();

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private ServerPrivateKeyConverter serverPrivateKeyConverter;

    @Autowired
    public void setServerPrivateKeyConverter(ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    /**
     * Method to retrieve the vault unlock key. Before calling this method, it is assumed that
     * client application performs signature validation - this method should not be called unauthenticated.
     * To indicate the signature validation result, 'isSignatureValid' boolean is passed as one of the
     * method parameters.
     *
     * @param activationId           Activation ID.
     * @param isSignatureValid       Information about validity of the signature.
     * @param keyConversionUtilities Key conversion utilities.
     * @return Vault unlock response with a properly encrypted vault unlock key.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public VaultUnlockResponse unlockVault(String activationId, boolean isSignatureValid, KeyConvertor keyConversionUtilities) throws GenericServiceException {
        try {
            // Find related activation record
            ActivationRecordEntity activation = powerAuthRepository.findActivationWithLock(activationId);

            if (activation != null && activation.getActivationStatus() == ActivationStatus.ACTIVE) {

                // Check if the signature is valid
                if (isSignatureValid) {

                    // Decrypt server private key (depending on encryption mode)
                    String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
                    EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
                    ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
                    String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);

                    // Get the server private and device public keys as byte[]
                    byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(serverPrivateKeyBase64);
                    byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
                    PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
                    PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

                    // Get encrypted vault unlock key and increment the counter
                    Long counter = activation.getCounter();

                    byte[] ctrBytes = ByteBuffer.allocate(16).putLong(0L).putLong(counter).array();
                    byte[] cKeyBytes = powerAuthServerVault.encryptVaultEncryptionKey(serverPrivateKey, devicePublicKey, ctrBytes);
                    activation.setCounter(counter + 1);
                    powerAuthRepository.save(activation);

                    // return the data
                    VaultUnlockResponse response = new VaultUnlockResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.ACTIVE));
                    response.setBlockedReason(null);
                    response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
                    response.setSignatureValid(true);
                    response.setUserId(activation.getUserId());
                    response.setEncryptedVaultEncryptionKey(BaseEncoding.base64().encode(cKeyBytes));

                    return response;

                } else {

                    // Even if the signature is not valid, increment the counter
                    Long counter = activation.getCounter();
                    activation.setCounter(counter + 1);
                    powerAuthRepository.save(activation);

                    // return the data
                    VaultUnlockResponse response = new VaultUnlockResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts() - activation.getFailedAttempts()));
                    response.setSignatureValid(false);
                    response.setUserId(activation.getUserId());
                    response.setEncryptedVaultEncryptionKey(null);

                    return response;
                }

            } else {

                // return the data
                VaultUnlockResponse response = new VaultUnlockResponse();
                response.setActivationId(activationId);
                response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.REMOVED));
                response.setBlockedReason(null);
                response.setRemainingAttempts(BigInteger.valueOf(0));
                response.setSignatureValid(false);
                response.setUserId("UNKNOWN");
                response.setEncryptedVaultEncryptionKey(null);

                return response;
            }
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

}
