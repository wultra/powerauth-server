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

package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

/**
 * Behavior class implementing the asymmetric (ECDSA) signature validation related processes. The
 * class separates the logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class AsymmetricSignatureServiceBehavior {

    private ActivationRepository activationRepository;
    private SignatureUtils signatureUtils = new SignatureUtils();

    @Autowired
    public AsymmetricSignatureServiceBehavior(ActivationRepository activationRepository) {
        this.activationRepository = activationRepository;
    }

    /**
     * Validate ECDSA signature for given data using public key associated with given activation ID.
     * @param activationId Activation ID to be used for device public key lookup.
     * @param data Data that were signed, in Base64 format.
     * @param signature Provided signature to be verified, in Base64 format.
     * @param keyConversionUtilities Key converter provided by the client code.
     * @return True in case signature validates for given data with provided public key, false otherwise.
     * @throws InvalidKeySpecException In case public key was corrupt.
     * @throws SignatureException In case it was not possible to validate the signature.
     * @throws InvalidKeyException In case public key was corrupt.
     */
    public boolean verifyECDSASignature(String activationId, String data, String signature, CryptoProviderUtil keyConversionUtilities) throws InvalidKeySpecException, SignatureException, InvalidKeyException {
        final ActivationRecordEntity activation = activationRepository.findActivation(activationId);
        byte[] devicePublicKeyData = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyData);
        return signatureUtils.validateECDSASignature(BaseEncoding.base64().decode(data), BaseEncoding.base64().decode(signature), devicePublicKey);
    }

}
