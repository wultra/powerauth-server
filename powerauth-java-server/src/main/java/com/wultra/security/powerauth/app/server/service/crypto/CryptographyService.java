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

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.security.KeyPair;

/**
 * Cryptography service API for PowerAuth server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
@AllArgsConstructor
public abstract class CryptographyService {

    /**
     * Generate a key pair for an application. The key pair can be composite in case of a hybrid algorithm.
     *
     * @param application Application.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract void generateMasterKeyPair(ApplicationEntity application) throws GenericServiceException;

    /**
     * Get a key pair for an application. The key pair can be composite in case of a hybrid algorithm.
     *
     * @param keyType Key type.
     * @param application Application.
     * @return Key pair.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract KeyPair getMasterKeyPair(KeyType keyType, ApplicationEntity application) throws GenericServiceException;

    /**
     * Derive shared secret key.
     * @param activation Activation.
     * @return Shared secret key.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract SecretKey deriveSharedSecretKey(ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Generate server key pair for an activation. The key pair can be composite in case of a hybrid algorithm.
     *
     * @param activation Activation.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract void generateServerKeyPair(ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Convert a device public key.
     * @param keyType Key type.
     * @param devicePublicKey Device public key bytes.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract BasePublicKey convertDevicePublicKey(KeyType keyType, byte[] devicePublicKey) throws GenericServiceException;

    /**
     * Store a device public key for an activation.
     * @param activation Activation.
     * @param devicePublicKey Device public key.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract void storeDevicePublicKey(ActivationRecordEntity activation, BasePublicKey devicePublicKey) throws GenericServiceException;

    /**
     * Generate an activation fingerprint.
     * @param activation Activation.
     * @return Activation fingerprint.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract String generateActivationFingerprint(ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Generate an asymmetric signature for an application.
     *
     * @param keyType Key type.
     * @param data Data to sign.
     * @param application Application entity.
     * @return Signature.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract byte[] generateSignatureForApplication(KeyType keyType, byte[] data, ApplicationEntity application) throws GenericServiceException;

    /**
     * Generate an asymmetric signature for an activation.
     *
     * @param keyType Key type.
     * @param data Data to sign.
     * @param activation Activation entity.
     * @return Signature.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract byte[] generateSignatureForActivation(KeyType keyType, byte[] data, ActivationRecordEntity activation) throws GenericServiceException;

    /**
     * Verify an asymmetric signature for an activation.
     *
     * @param keyType Key type.
     * @param data Data used for calculating signature.
     * @param signature Signature.
     * @param activation Activation.
     * @return True in case signature is valid, false otherwise.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract boolean verifySignatureForActivation(KeyType keyType, byte[] data, byte[] signature, ActivationRecordEntity activation) throws GenericServiceException;

}
