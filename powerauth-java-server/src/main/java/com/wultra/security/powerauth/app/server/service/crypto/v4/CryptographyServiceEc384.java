/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.service.crypto.v4;

import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.crypto.BaseKeyPair;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

/**
 * Cryptography Service V4 implementation based on EC curve P-384.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class CryptographyServiceEc384 implements CryptographyService {

    @Override
    public void generateMasterKeyPair(String applicationId) {
        // TODO
    }

    @Override
    public BaseKeyPair getMasterKeyPair(String applicationId) {
        // TODO
        return null;
    }

    @Override
    public SecretKey generateSharedSecretKey(String activationId) throws GenericServiceException {
        return null;
    }

    @Override
    public void generateDeviceKeyPair(String activationId) throws GenericServiceException {
        // TODO
    }

    @Override
    public void storeDevicePublicKey(String activationId, BasePublicKey devicePublicKey) throws GenericServiceException {
        // TODO
    }

    @Override
    public String generateActivationFingerprint(String activationId) throws GenericServiceException {
        return "";
    }

    @Override
    public byte[] generateSignatureForApplication(byte[] data, String applicationId) throws GenericServiceException {
        // TODO
        return new byte[0];
    }

    @Override
    public byte[] generateSignatureForActivation(byte[] data, String activationId) throws GenericServiceException {
        // TODO
        return new byte[0];
    }

    @Override
    public boolean verifySignatureForActivation(byte[] data, byte[] signature, String activationId) throws GenericServiceException {
        // TODO
        return false;
    }

    @Override
    public DecryptionResult decryptRequest(EncryptedRequest encryptedRequest, EncryptionContext context) {
        // TODO
        return null;
    }

    @Override
    public EncryptorSecrets deriveSecrets(EncryptedRequest request, EncryptionContext context) {
        // TODO
        return null;
    }

    @Override
    public String requestTemporaryKey(String jwt) throws GenericServiceException {
        return "";
    }

}
