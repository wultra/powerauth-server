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

package com.wultra.powerauth.fido2.service.provider;

import com.wultra.powerauth.fido2.rest.model.entity.*;

/**
 * Interface representing FIDO2 verification service.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface CryptographyService {

    /**
     * Verify signature for a registration.
     *
     * @param applicationId Application identifier.
     * @param clientDataJSON Collected client data.
     * @param authData Authenticator data.
     * @param signature Signature bytes.
     * @param attestedCredentialData Attested credential data.
     * @return Whether signature verification succeeded.
     * @throws Exception Thrown in case of a cryptography error.
     */
    boolean verifySignatureForRegistration(String applicationId, CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] signature, AttestedCredentialData attestedCredentialData) throws Exception;

    /**
     * Verify signature for an assertion.
     *
     * @param applicationId Application identifier.
     * @param credentialId Credential identifier.
     * @param clientDataJSON Collected client data.
     * @param authData Authenticator data.
     * @param signature Signature bytes.
     * @param authenticatorDetail Authenticator detail.
     * @return Whether signature verification succeeded.
     * @throws Exception Thrown in case of a cryptography error.
     */
    boolean verifySignatureForAssertion(String applicationId, String credentialId, CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] signature, AuthenticatorDetail authenticatorDetail) throws Exception;

    /**
     * Convert public key object to bytes.
     *
     * @param publicKey Public key object.
     * @return Public key bytes.
     * @throws Exception Thrown in case of a cryptography error.
     */
    byte[] publicKeyToBytes(PublicKeyObject publicKey) throws Exception;

}
