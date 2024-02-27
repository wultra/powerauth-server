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
 */

package io.getlime.security.powerauth.app.server.service.fido2;

import com.wultra.powerauth.fido2.rest.model.entity.*;
import com.wultra.powerauth.fido2.service.provider.CryptographyService;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

/**
 * Service providing FIDO2 cryptographic functionality.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class PowerAuthCryptographyService implements CryptographyService {

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final ActivationRepository activationRepository;

    public PowerAuthCryptographyService(ActivationRepository activationRepository) {
        this.activationRepository = activationRepository;
    }

    public boolean verifySignatureForAssertion(String applicationId, String authenticatorId, CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] signature, AuthenticatorDetail authenticatorDetail) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException, InvalidKeyException {
        if (!checkAndPersistCounter(applicationId, authenticatorId, authData.getSignCount())) {
            return false;
        }
        final byte[] publicKeyBytes = authenticatorDetail.getPublicKeyBytes();
        final PublicKey publicKey = keyConvertor.convertBytesToPublicKey(publicKeyBytes);
        return verifySignature(clientDataJSON, authData, signature, publicKey);
    }

    public boolean verifySignatureForRegistration(String applicationId, CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] signature, AttestedCredentialData attestedCredentialData) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException, InvalidKeyException {
        final ECPoint point = attestedCredentialData.getPublicKeyObject().getPoint();
        final PublicKey publicKey = keyConvertor.convertPointBytesToPublicKey(point.getX(), point.getY());
        return verifySignature(clientDataJSON, authData, signature, publicKey);
    }

    public byte[] publicKeyToBytes(PublicKeyObject publicKey) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException {
        final ECPoint point = publicKey.getPoint();
        final PublicKey publicKeyConverted = keyConvertor.convertPointBytesToPublicKey(point.getX(), point.getY());
        return keyConvertor.convertPublicKeyToBytes(publicKeyConverted);
    }

    // private methods


    private boolean verifySignature(CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] signature, PublicKey publicKey) throws GenericCryptoException, CryptoProviderException, InvalidKeyException {
        final byte[] clientDataJSONEncodedHash = concat(authData.getEncoded(), Hash.sha256(clientDataJSON.getEncoded()));
        final SignatureUtils signatureUtils = new SignatureUtils();
        return signatureUtils.validateECDSASignature(clientDataJSONEncodedHash, signature, publicKey);
    }

    private boolean checkAndPersistCounter(String applicationId, String authenticatorId, int signCount) {
        final List<ActivationRecordEntity> activations = activationRepository.findByExternalId(applicationId, authenticatorId);
        if (activations.isEmpty()) {
            logger.warn("Activation not found, external ID: {}", authenticatorId);
            return false;
        }
        if (activations.size() > 1) {
            logger.warn("Multiple activations with same external ID found, external ID: {}", authenticatorId);
            return false;
        }
        final ActivationRecordEntity activation = activations.get(0);
        if (signCount == 0 && activation.getCounter() == 0) {
            return true;
        }
        if (activation.getCounter() >= signCount) {
            logger.warn("Invalid counter value for activation, activation ID: {}, stored counter value: {}, received counter value: {}", activation.getActivationId(), activation.getCounter(), signCount);
            return false;
        }
        activation.setCounter((long) signCount);
        activationRepository.save(activation);
        return true;
    }

    private byte[] concat(byte[] a, byte[] b) {
        final byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return combined;
    }

}
