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

package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.v3.VaultUnlockResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

/**
 * Behavior class implementing the vault unlock related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component("VaultUnlockServiceBehavior")
public class VaultUnlockServiceBehavior {

    private ActivationRepository powerAuthRepository;

    @Autowired
    public VaultUnlockServiceBehavior(ActivationRepository powerAuthRepository) {
        this.powerAuthRepository = powerAuthRepository;
    }

    private final PowerAuthServerVault powerAuthServerVault = new PowerAuthServerVault();

    // Prepare converters
    private ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
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
     * @throws InvalidKeySpecException In case invalid key is provided.
     * @throws InvalidKeyException     In case invalid key is provided.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public VaultUnlockResponse unlockVault(String activationId, boolean isSignatureValid, CryptoProviderUtil keyConversionUtilities) throws InvalidKeySpecException, InvalidKeyException, GenericServiceException {
        throw new IllegalStateException("Not implemented yet");
    }

}
