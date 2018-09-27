package io.getlime.security.powerauth.app.server.service.behavior.common;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.converter.v3.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.KeyEncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Service used for derivation of keys, shared by behaviors.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class KeyDerivationService {

    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final CryptoProviderUtil keyConversionUtilities = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    /**
     * Service constructor.
     * @param serverPrivateKeyConverter Autowired converter for server private key.
     */
    @Autowired
    public KeyDerivationService(ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    /**
     * Derive transport key for an activation.
     *
     * @param activation Activation entity.
     * @return Derived transport key.
     * @throws GenericServiceException Thrown when server private key could not be loaded from database.
     * @throws InvalidKeySpecException Thrown when key spec is invalid.
     * @throws InvalidKeyException Thrown when key is invalid.
     */
    public byte[] deriveTransportKey(ActivationRecordEntity activation) throws GenericServiceException, InvalidKeySpecException, InvalidKeyException {
        // Get the device public key
        String devicePublicKeyBase64 = activation.getDevicePublicKeyBase64();

        // Get the server private key, decrypt it if required
        String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
        KeyEncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
        String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity, activation.getUserId(), activation.getActivationId());

        // Convert keys from  bytes
        PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(serverPrivateKeyBase64));
        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(devicePublicKeyBase64));

        // Compute master secret key using ECDH
        SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

        // Derive transport key from master secret key
        SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);
        return keyConversionUtilities.convertSharedSecretKeyToBytes(transportKey);
    }
}
