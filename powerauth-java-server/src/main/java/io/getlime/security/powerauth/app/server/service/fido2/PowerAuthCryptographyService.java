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

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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
    private final Fido2CertificateValidator certificateValidator;

    public PowerAuthCryptographyService(ActivationRepository activationRepository, Fido2CertificateValidator certificateValidator) {
        this.activationRepository = activationRepository;
        this.certificateValidator = certificateValidator;
    }

    public boolean verifySignatureForAssertion(String applicationId, String authenticatorId, CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] signature, AuthenticatorDetail authenticatorDetail) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException, InvalidKeyException {
        if (!checkAndPersistCounter(applicationId, authenticatorId, authData.getSignCount())) {
            return false;
        }
        final byte[] publicKeyBytes = authenticatorDetail.getPublicKeyBytes();
        final PublicKey publicKey = keyConvertor.convertBytesToPublicKey(publicKeyBytes);
        return verifySignature(clientDataJSON, authData, signature, publicKey);
    }

    public boolean verifySignatureForRegistration(String applicationId, CollectedClientData clientDataJSON, AttestationObject attestationObject, byte[] signature) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException, InvalidKeyException {
        final Optional<ECPoint> pointOptional = resolveEcPoint(attestationObject);
        if (pointOptional.isEmpty()) {
            logger.warn("Signature could not be verified because public key point is missing");
            return false;
        }
        final ECPoint point = pointOptional.get();
        final PublicKey publicKey = keyConvertor.convertPointBytesToPublicKey(point.getX(), point.getY());
        return verifySignature(clientDataJSON, attestationObject.getAuthData(), signature, publicKey);
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

    /**
     * Resolve EC point which is used for public key in attestation verification.
     * @param attestationObject Attestation object.
     * @return EC point (optional).
     */
    private Optional<ECPoint> resolveEcPoint(AttestationObject attestationObject) {
        final AuthenticatorData authData = attestationObject.getAuthData();
        final AttestedCredentialData attestedCredentialData = authData.getAttestedCredentialData();
        final Optional<ECPoint> result;
        switch (attestationObject.getAttStmt().getAttestationType()) {
            case NONE -> {
                logger.warn("Invalid attestation type NONE for attestation format: {}", attestationObject.getFmt());
                result = Optional.empty();
            }
            case SELF -> {
                logger.debug("Using public key from Self attestation");
                result = Optional.of(attestedCredentialData.getPublicKeyObject().getPoint());
            }
            case BASIC -> {
                logger.debug("Using public key from Basic attestation");
                final byte[] attestationCert = attestationObject.getAttStmt().getX509Cert().getAttestationCert();
                final List<byte[]> attestationCaCerts = attestationObject.getAttStmt().getX509Cert().getCaCerts();
                final X509Certificate cert;
                final List<X509Certificate> caCerts = new ArrayList<>();
                try {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    final ByteArrayInputStream inputStream = new ByteArrayInputStream(attestationCert);
                    cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
                    if (attestationCaCerts != null) {
                        attestationCaCerts.forEach(caCert -> {
                            final ByteArrayInputStream is = new ByteArrayInputStream(caCert);
                            try {
                                caCerts.add((X509Certificate) certificateFactory.generateCertificate(is));
                            } catch (CertificateException e) {
                                logger.debug(e.getMessage(), e);
                                logger.warn("Invalid CA certificate received in Basic attestation, error: {}", e.getMessage());
                            }
                        });
                    }
                } catch (CertificateException e) {
                    logger.debug(e.getMessage(), e);
                    logger.warn("Invalid certificate received in Basic attestation, error: {}", e.getMessage());
                    result = Optional.empty();
                    break;
                }
                if (!(cert.getPublicKey() instanceof ECPublicKey)) {
                    logger.warn("Invalid cryptography algorithm used in Basic attestation, algorithm: {}", cert.getPublicKey().getAlgorithm());
                    result = Optional.empty();
                    break;
                }
                if (!certificateValidator.isValid(cert, caCerts, authData.getAttestedCredentialData().getAaguid())) {
                    logger.warn("Certificate validation failed in Basic attestation, subject name: {}", cert.getSubjectX500Principal().getName());
                    result = Optional.empty();
                    break;
                }
                result = Optional.of(convertPoint(((ECPublicKey) cert.getPublicKey()).getW()));
            }
            default -> result = Optional.empty();
        }
        return result;
    }

    /**
     * Convert {@link java.security.spec.ECPoint} from JavaSecurity to {@link com.wultra.powerauth.fido2.rest.model.entity.ECPoint}.
     * @param p {@link java.security.spec.ECPoint} from Java Security.
     * @return {@link com.wultra.powerauth.fido2.rest.model.entity.ECPoint}
     */
    private ECPoint convertPoint(java.security.spec.ECPoint p) {
        final ECPoint result = new ECPoint();
        result.setX(p.getAffineX().toByteArray());
        result.setY(p.getAffineY().toByteArray());
        return result;
    }

}
