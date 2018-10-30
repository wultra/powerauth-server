package io.getlime.security.powerauth.app.server.service.behavior.util;

import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Utility class used for derivation of keys, shared by behaviors.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KeyDerivationUtil {

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final CryptoProviderUtil keyConversionUtilities = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    /**
     * Derive transport key for an activation.
     *
     * @param serverPrivateKeyBytes Server private key bytes.
     * @param devicePublicKeyBytes Device public key bytes.
     * @return Derived transport key.
     * @throws GenericServiceException Thrown when server private key could not be loaded from database.
     * @throws InvalidKeySpecException Thrown when key spec is invalid.
     * @throws InvalidKeyException Thrown when key is invalid.
     */
    public byte[] deriveTransportKey(byte[] serverPrivateKeyBytes, byte[] devicePublicKeyBytes) throws GenericServiceException, InvalidKeySpecException, InvalidKeyException {
        // Convert keys from bytes
        PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

        // Compute master secret key using ECDH
        SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

        // Derive transport key from master secret key
        SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);
        return keyConversionUtilities.convertSharedSecretKeyToBytes(transportKey);
    }
}
