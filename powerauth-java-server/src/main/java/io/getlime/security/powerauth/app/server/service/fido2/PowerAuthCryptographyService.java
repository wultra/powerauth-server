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
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationConfigEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationConfigRepository;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
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

import static com.wultra.powerauth.fido2.rest.model.enumeration.Fido2ConfigKeys.CONFIG_KEY_ROOT_CA_CERTS;

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
    private final ActivationQueryService activationQueryService;
    private final ApplicationConfigRepository applicationConfigRepository;
    private final Fido2CertificateValidator certificateValidator;

    public PowerAuthCryptographyService(ActivationRepository activationRepository, ActivationQueryService activationQueryService, ApplicationConfigRepository applicationConfigRepository, Fido2CertificateValidator certificateValidator) {
        this.activationRepository = activationRepository;
        this.activationQueryService = activationQueryService;
        this.applicationConfigRepository = applicationConfigRepository;
        this.certificateValidator = certificateValidator;
    }

    public boolean verifySignatureForAssertion(String applicationId, String credentialId, CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] signature, AuthenticatorDetail authenticatorDetail) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException, InvalidKeyException {
        if (!checkAndPersistCounter(applicationId, credentialId, authData.getSignCount())) {
            return false;
        }
        byte[] dataSuffix = null;
        final String aaguid = (String) authenticatorDetail.getExtras().get("aaguid");
        if (aaguid != null && Fido2DefaultAuthenticators.isWultraModel(aaguid)) {
            dataSuffix = getOperationDataBytes(clientDataJSON.getChallenge());
            if (dataSuffix == null) {
                logger.debug("Visual challenge expected, but no data found to append.");
                return false;
            }
        }
        final byte[] publicKeyBytes = authenticatorDetail.getPublicKeyBytes();
        final PublicKey publicKey = keyConvertor.convertBytesToPublicKey(publicKeyBytes);
        return verifySignature(clientDataJSON, authData, dataSuffix, signature, publicKey);
    }

    public boolean verifySignatureForRegistration(String applicationId, CollectedClientData clientDataJSON, AttestationObject attestationObject, byte[] signature) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException, InvalidKeyException {
        final Optional<ECPoint> pointOptional = resolveEcPoint(attestationObject, applicationId);
        if (pointOptional.isEmpty()) {
            logger.warn("Signature could not be verified because public key point is missing");
            return false;
        }
        final ECPoint point = pointOptional.get();
        final PublicKey publicKey = keyConvertor.convertPointBytesToPublicKey(point.getX(), point.getY());
        return verifySignature(clientDataJSON, attestationObject.getAuthData(), null, signature, publicKey);
    }

    public byte[] publicKeyToBytes(PublicKeyObject publicKey) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException {
        final ECPoint point = publicKey.getPoint();
        final PublicKey publicKeyConverted = keyConvertor.convertPointBytesToPublicKey(point.getX(), point.getY());
        return keyConvertor.convertPublicKeyToBytes(publicKeyConverted);
    }

    // private methods


    private boolean verifySignature(CollectedClientData clientDataJSON, AuthenticatorData authData, byte[] dataSuffix, byte[] signature, PublicKey publicKey) throws GenericCryptoException, CryptoProviderException, InvalidKeyException {
        final byte[] signableData;
        if (dataSuffix != null) {
            signableData = ByteUtils.concat(authData.getEncoded(), Hash.sha256(clientDataJSON.getEncoded()), dataSuffix);
        } else {
            signableData = ByteUtils.concat(authData.getEncoded(), Hash.sha256(clientDataJSON.getEncoded()));
        }
        final SignatureUtils signatureUtils = new SignatureUtils();
        return signatureUtils.validateECDSASignature(signableData, signature, publicKey);
    }

    private boolean checkAndPersistCounter(String applicationId, String credentialId, int signCount) {
        final List<ActivationRecordEntity> activations = activationQueryService.findByExternalId(applicationId, credentialId);
        if (activations.isEmpty()) {
            logger.warn("Activation not found, external ID: {}", credentialId);
            return false;
        }
        if (activations.size() > 1) {
            logger.warn("Multiple activations with same external ID found, external ID: {}", credentialId);
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

    /**
     * Parse challenge value to obtain operation data presented to the user via the visual challenge.
     *
     * @param challenge Challenge value in the expected format `operation_id&operation_data`.
     * @return Value of operation data, as UTF-8 encoded bytes.
     */
    private static byte[] getOperationDataBytes(String challenge) {
        final String[] split = challenge.split("&", 2);
        if (split.length != 2) {
            return null;
        }
        return split[1].getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Resolve EC point which is used for public key in attestation verification.
     *
     * @param attestationObject Attestation object.
     * @param applicationId     Application ID.
     * @return EC point (optional).
     */
    private Optional<ECPoint> resolveEcPoint(AttestationObject attestationObject, String applicationId) {
        final AuthenticatorData authData = attestationObject.getAuthData();
        final AttestedCredentialData attestedCredentialData = authData.getAttestedCredentialData();
        return switch (attestationObject.getAttStmt().getAttestationType()) {
            case NONE -> {
                logger.warn("Invalid attestation type NONE for attestation format: {}", attestationObject.getFmt());
                yield Optional.empty();
            }
            case SELF -> {
                logger.debug("Using public key from Self attestation");
                yield Optional.of(attestedCredentialData.getPublicKeyObject().getPoint());
            }
            case BASIC -> {
                logger.debug("Using public key from Basic attestation");
                final byte[] attestationCert = attestationObject.getAttStmt().getX509Cert().getAttestationCert();
                final List<byte[]> attestationCertChain = attestationObject.getAttStmt().getX509Cert().getCertChain();
                final X509Certificate validatedCert;
                final List<X509Certificate> intermediateCerts;
                final List<X509Certificate> rootCerts;
                try {
                    validatedCert = convertCert(attestationCert);
                    intermediateCerts = convertCertChain(attestationCertChain);
                    rootCerts = getRootCaCerts(applicationId);
                } catch (CertificateException e) {
                    logger.debug(e.getMessage(), e);
                    logger.warn("Invalid certificate received in Basic attestation, error: {}", e.getMessage());
                    yield Optional.empty();
                }
                if (!(validatedCert.getPublicKey() instanceof ECPublicKey)) {
                    logger.warn("Invalid cryptography algorithm used in Basic attestation, algorithm: {}", validatedCert.getPublicKey().getAlgorithm());
                    yield Optional.empty();
                }
                if (!certificateValidator.isValid(validatedCert, intermediateCerts, rootCerts, authData.getAttestedCredentialData().getAaguid())) {
                    logger.warn("Certificate validation failed in Basic attestation, subject name: {}", validatedCert.getSubjectX500Principal().getName());
                    yield Optional.empty();
                }
                yield Optional.of(convertPoint(((ECPublicKey) validatedCert.getPublicKey()).getW()));
            }
        };
    }

    /**
     * Convert certificate from byte array to an X.509 certificate.
     * @param cert Certificate as byte array.
     * @return X.509 certificate
     * @throws CertificateException In case certificate conversion fails.
     */
    private X509Certificate convertCert(byte[] cert) throws CertificateException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(cert);
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    /**
     * Convert certificate chain from byte array to list of X.509 certificates.
     * @param certChain Certificate chain as byte array.
     * @return List of X.509 certificates.
     * @throws CertificateException In case of invalid certificate.
     */
    private List<X509Certificate> convertCertChain(List<byte[]> certChain) throws CertificateException {
        final List<X509Certificate> result = new ArrayList<>();
        if (certChain != null) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            certChain.forEach(caCert -> {
                final ByteArrayInputStream is = new ByteArrayInputStream(caCert);
                try {
                    result.add((X509Certificate) certificateFactory.generateCertificate(is));
                } catch (CertificateException e) {
                    logger.debug(e.getMessage(), e);
                    logger.warn("Invalid CA certificate received in Basic attestation, error: {}", e.getMessage());
                }
            });
        }
        return result;
    }


    /**
     * Get list of root CA certificates from application settings.
     * @param applicationId Application ID.
     * @return List of root CA certificates.
     * @throws CertificateException In case any certificate is invalid.
     */
    private List<X509Certificate> getRootCaCerts(String applicationId) throws CertificateException {
        final List<X509Certificate> rootCaCerts = new ArrayList<>();
        final Optional<ApplicationConfigEntity> appConfigOptional = applicationConfigRepository.findByApplicationIdAndKey(applicationId, CONFIG_KEY_ROOT_CA_CERTS);
        if (appConfigOptional.isPresent()) {
            final List<String> certs = appConfigOptional.get().getValues();
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            certs.forEach(certPem -> {
                final ByteArrayInputStream is = new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8));
                try {
                    final X509Certificate rootCert = (X509Certificate) certFactory.generateCertificate(is);
                    rootCaCerts.add(rootCert);
                } catch (CertificateException e) {
                    logger.debug(e.getMessage(), e);
                    logger.warn("Invalid certificate configured, error: {}", e.getMessage());
                }
            });
        }
        return rootCaCerts;
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
