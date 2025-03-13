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

package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.crypto.BaseKeyPair;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;

import javax.crypto.SecretKey;

/**
 * Cryptography service API for PowerAuth server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface CryptographyService {

    /**
     * Generate a key pair for an application. The key pair can be composite in case of a hybrid algorithm.
     *
     * @param application Application.
     * @throws GenericServiceException In case of a cryptography error.
     */
    void generateMasterKeyPair(ApplicationEntity application) throws GenericServiceException;

    /**
     * Get a key pair for an application. The key pair can be composite in case of a hybrid algorithm.
     *
     * @param application Application.
     * @return Key pair.
     * @throws GenericServiceException In case of a cryptography error.
     */
    BaseKeyPair getMasterKeyPair(ApplicationEntity application) throws GenericServiceException;

    /**
     * Generate shared secret key.
     * @param activation Activation.
     * @return Shared secret key.
     * @throws GenericServiceException In case of a cryptography error.
     */
    SecretKey generateSharedSecretKey(ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Generate a key pair for an activation. The key pair can be composite in case of a hybrid algorithm.
     *
     * @param activation Activation.
     * @throws GenericServiceException In case of a cryptography error.
     */
    void generateDeviceKeyPair(ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Convert a device public key.
     * @param devicePublicKey Device public key bytes.
     * @throws GenericServiceException In case of a cryptography error.
     */
    BasePublicKey convertDevicePublicKey(byte[] devicePublicKey) throws GenericServiceException;

    /**
     * Store a device public key for an activation.
     * @param activation Activation.
     * @param devicePublicKey Device public key.
     * @throws GenericServiceException In case of a cryptography error.
     */
    void storeDevicePublicKey(ActivationRecordEntity activation, BasePublicKey devicePublicKey) throws GenericServiceException;

    /**
     * Generate an activation fingerprint.
     * @param activation Activation.
     * @return Activation fingerprint.
     * @throws GenericServiceException In case of a cryptography error.
     */
    String generateActivationFingerprint(ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Generate an asymmetric signature for an application.
     *
     * @param data Data to sign.
     * @param application Application identifier.
     * @return Signature.
     * @throws GenericServiceException In case of a cryptography error.
     */
    byte[] generateSignatureForApplication(byte[] data, ApplicationEntity application) throws GenericServiceException;

    /**
     * Generate an asymmetric signature for an activation.
     *
     * @param data Data to sign.
     * @param activation Activation identifier.
     * @return Signature.
     * @throws GenericServiceException In case of a cryptography error.
     */
    byte[] generateSignatureForActivation(byte[] data, ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Verify an asymmetric signature for an activation.
     *
     * @param data Data used for calculating signature.
     * @param signature Signature.
     * @param activation Activation.
     * @return True in case signature is valid, false otherwise.
     * @throws GenericServiceException In case of a cryptography error.
     */
    boolean verifySignatureForActivation(byte[] data, byte[] signature, ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Decrypt an encrypted request using server encryptor.
     *
     * @param encryptedRequest Encrypted request.
     * @param context Encryption context.
     * @return Decrypted data and context.
     * @throws GenericServiceException In case of a cryptography error.
     */
    DecryptionResult decryptRequest(EncryptedRequest encryptedRequest, EncryptionContext context) throws GenericServiceException;

    /**
     * Derive encryptor secrets.
     *
     * @param request Encrypted request without encrypted data.
     * @param context Encryption context.
     * @return Encryptor secrets.
     * @throws GenericServiceException In case of a cryptography error.
     */
    EncryptorSecrets deriveSecrets(EncryptedRequest request, EncryptionContext context) throws GenericServiceException;

    /**
     * Request a temporary key.
     * @param jwt Temporary key request in JWT format.
     * @return Temporary key in JWT format.
     * @throws GenericServiceException In case of a cryptography error.
     */
    String requestTemporaryKey(String jwt) throws GenericServiceException;

}
