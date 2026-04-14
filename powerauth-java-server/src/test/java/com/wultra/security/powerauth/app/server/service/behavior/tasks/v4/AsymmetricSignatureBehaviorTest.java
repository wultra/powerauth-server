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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureFormat;
import com.wultra.security.powerauth.client.model.enumeration.v4.AsymmetricSignatureType;
import com.wultra.security.powerauth.client.model.request.v4.SignAsymmetricRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAsymmetricSignatureRequest;
import com.wultra.security.powerauth.client.model.response.v4.SignAsymmetricResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAsymmetricSignatureResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Test for {@link AsymmetricSignatureServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class AsymmetricSignatureBehaviorTest {

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private ActivationQueryService activationQueryService;

    @Mock
    private ActivationContextValidator activationValidator;

    @Mock
    private CryptographyServiceFactory cryptographyServiceFactory;

    @Mock
    private CryptographyService cryptographyService;

    @InjectMocks
    private AsymmetricSignatureServiceBehavior tested;

    private ActivationRecordEntity activationV4L3;
    private ActivationRecordEntity activationV4L5;
    private ActivationRecordEntity activationV3;
    private final byte[] dataToSign = "DataToSign".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        activationV4L3 = new ActivationRecordEntity();
        activationV4L3.setActivationStatus(ActivationStatus.ACTIVE);
        activationV4L3.setProtocol(ActivationProtocol.POWERAUTH);
        activationV4L3.setCryptoAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        activationV4L3.setVersion(4);
        activationV4L5 = new ActivationRecordEntity();
        activationV4L5.setActivationStatus(ActivationStatus.ACTIVE);
        activationV4L5.setProtocol(ActivationProtocol.POWERAUTH);
        activationV4L5.setCryptoAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L5);
        activationV4L5.setVersion(4);
        activationV3 = new ActivationRecordEntity();
        activationV3.setActivationStatus(ActivationStatus.ACTIVE);
        activationV3.setProtocol(ActivationProtocol.POWERAUTH);
        activationV3.setVersion(3);
    }

    @Test
    void signDataValid() throws Exception {
        String activationId = "78f184f2-c434-474f-971e-9c2d255faf8c";
        String dataBase64 = Base64.getEncoder().encodeToString(dataToSign);

        String signatureEcdsa = "MGUCMHSj/atLUNwJrM0q8+PTtvNPpftHSGX3ErcyCwqfqZ0Ia627POEla+gaAcALqdLGjAIxAMa19AkR63k4HItcvqDcOuhgKv+E5PFcWXF1dkpgNq7jjvBMM3G1jYt7dG+DsVF71Q==";
        String signatureMldsa = "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";

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activationV4L3));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.generateSignatureForActivation(eq(KeyType.ECDSA_P384), eq(dataToSign), eq(activationV4L3)))
                .thenReturn(Base64.getDecoder().decode(signatureEcdsa));
        when(cryptographyService.generateSignatureForActivation(eq(KeyType.MLDSA_65), eq(dataToSign), eq(activationV4L3)))
                .thenReturn(Base64.getDecoder().decode(signatureMldsa));

        SignAsymmetricRequest request = new SignAsymmetricRequest();
        request.setActivationId(activationId);
        request.setData(dataBase64);

        SignAsymmetricResponse response = tested.signData(request);

        assertEquals(signatureEcdsa, response.getSignatureEcdsa());
        assertEquals(signatureMldsa, response.getSignatureMldsa());
    }

    @Test
    void signDataThrow_invalidState() {
        activationV4L3.setActivationStatus(ActivationStatus.REMOVED);
        when(activationQueryService.findActivationWithoutLock("78f184f2-c434-474f-971e-9c2d255faf8c")).thenReturn(Optional.of(activationV4L3));
        when(localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_INCORRECT_STATE, "Invalid activation state"));

        SignAsymmetricRequest request = new SignAsymmetricRequest();
        request.setActivationId("78f184f2-c434-474f-971e-9c2d255faf8c");
        request.setData(Base64.getEncoder().encodeToString(dataToSign));

        assertThrows(GenericServiceException.class, () -> tested.signData(request));
    }

    @Test
    void signDataThrow_activationNotFound() {
        when(activationQueryService.findActivationWithoutLock("78f184f2-c434-474f-971e-9c2d255faf8c")).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_NOT_FOUND, "Activation not found"));

        SignAsymmetricRequest request = new SignAsymmetricRequest();
        request.setActivationId("78f184f2-c434-474f-971e-9c2d255faf8c");
        request.setData(Base64.getEncoder().encodeToString(dataToSign));

        assertThrows(GenericServiceException.class, () -> tested.signData(request));
    }

    @Test
    void verifySignatureValid_Ecdsa() throws Exception {
        String encodedData = "RGF0YVRvU2lnbg==";
        String base64Signature = "MGUCMHSj/atLUNwJrM0q8+PTtvNPpftHSGX3ErcyCwqfqZ0Ia627POEla+gaAcALqdLGjAIxAMa19AkR63k4HItcvqDcOuhgKv+E5PFcWXF1dkpgNq7jjvBMM3G1jYt7dG+DsVF71Q==";

        byte[] derSignature = Base64.getDecoder().decode(base64Signature);
        byte[] dataBytes = Base64.getDecoder().decode(encodedData);

        VerifyAsymmetricSignatureRequest request = new VerifyAsymmetricSignatureRequest();
        request.setActivationId("78f184f2-c434-474f-971e-9c2d255faf8c");
        request.setData(encodedData);
        request.setSignature(base64Signature);
        request.setSignatureFormat(AsymmetricSignatureFormat.DER);
        request.setSignatureType(AsymmetricSignatureType.ECDSA);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activationV4L3));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.ECDSA_P384), eq(dataBytes), eq(derSignature), eq(activationV4L3)))
                .thenReturn(true);

        VerifyAsymmetricSignatureResponse response = tested.verifySignature(request);
        assertTrue(response.isSignatureValid());
    }

    @Test
    void verifySignatureValid_Ecdsa_Legacy() throws Exception {
        String encodedData = "RGF0YVRvU2lnbg==";
        String base64Signature = "MEUCIQDYp+isOdLi9kcWDu9gZxHeUnFxbjqFpIGOSbd5lDpqngIgC/KP0rP5R1bu6pZRufD4vcqieq03I/lvN/7m4FpaI2A=";

        byte[] derSignature = Base64.getDecoder().decode(base64Signature);
        byte[] dataBytes = Base64.getDecoder().decode(encodedData);

        VerifyAsymmetricSignatureRequest request = new VerifyAsymmetricSignatureRequest();
        request.setActivationId("8ff9ad77-2aff-4edf-8e27-8b08db8a6811");
        request.setData(encodedData);
        request.setSignature(base64Signature);
        request.setSignatureFormat(AsymmetricSignatureFormat.DER);
        request.setSignatureType(AsymmetricSignatureType.ECDSA);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activationV3));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.ECDSA_P256), eq(dataBytes), eq(derSignature), eq(activationV3)))
                .thenReturn(true);

        VerifyAsymmetricSignatureResponse response = tested.verifySignature(request);
        assertTrue(response.isSignatureValid());
    }

    @Test
    void verifySignatureValid_Mldsa65() throws Exception {
        String encodedData = "RGF0YVRvU2lnbg==";
        String base64Signature = "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";

        byte[] mldsaSignature = Base64.getDecoder().decode(base64Signature);
        byte[] dataBytes = Base64.getDecoder().decode(encodedData);

        VerifyAsymmetricSignatureRequest request = new VerifyAsymmetricSignatureRequest();
        request.setActivationId("78f184f2-c434-474f-971e-9c2d255faf8c");
        request.setData(encodedData);
        request.setSignature(Base64.getEncoder().encodeToString(mldsaSignature));
        request.setSignatureFormat(AsymmetricSignatureFormat.DER);
        request.setSignatureType(AsymmetricSignatureType.MLDSA);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activationV4L3));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.MLDSA_65), eq(dataBytes), eq(mldsaSignature), eq(activationV4L3)))
                .thenReturn(true);

        VerifyAsymmetricSignatureResponse response = tested.verifySignature(request);
        assertTrue(response.isSignatureValid());
    }

    @Test
    void verifySignatureValid_Mldsa87() throws Exception {
        String encodedData = "RGF0YVRvU2lnbg==";
        String base64Signature = "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";

        byte[] mldsaSignature = Base64.getDecoder().decode(base64Signature);
        byte[] dataBytes = Base64.getDecoder().decode(encodedData);

        VerifyAsymmetricSignatureRequest request = new VerifyAsymmetricSignatureRequest();
        request.setActivationId("78f184f2-c434-474f-971e-9c2d255faf8c");
        request.setData(encodedData);
        request.setSignature(Base64.getEncoder().encodeToString(mldsaSignature));
        request.setSignatureFormat(AsymmetricSignatureFormat.DER);
        request.setSignatureType(AsymmetricSignatureType.MLDSA);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activationV4L5));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.MLDSA_87), eq(dataBytes), eq(mldsaSignature), eq(activationV4L5)))
                .thenReturn(true);

        VerifyAsymmetricSignatureResponse response = tested.verifySignature(request);
        assertTrue(response.isSignatureValid());
    }

    @Test
    void verifySignatureThrows_invalidFormat() {
        VerifyAsymmetricSignatureRequest request = new VerifyAsymmetricSignatureRequest();
        request.setActivationId("78f184f2-c434-474f-971e-9c2d255faf8c");
        request.setData(Base64.getEncoder().encodeToString(dataToSign));
        request.setSignature(Base64.getEncoder().encodeToString("sig".getBytes()));
        request.setSignatureFormat(AsymmetricSignatureFormat.JOSE);
        request.setSignatureType(AsymmetricSignatureType.MLDSA);

        when(localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        assertThrows(GenericServiceException.class, () -> tested.verifySignature(request));
    }

    @Test
    void verifySignatureVerifyFail_activationNotFound() throws GenericServiceException {
        when(activationQueryService.findActivationWithoutLock("78f184f2-c434-474f-971e-9c2d255faf8c")).thenReturn(Optional.empty());

        VerifyAsymmetricSignatureRequest request = new VerifyAsymmetricSignatureRequest();
        request.setActivationId("78f184f2-c434-474f-971e-9c2d255faf8c");
        request.setData(Base64.getEncoder().encodeToString(dataToSign));
        request.setSignature(Base64.getEncoder().encodeToString("sig".getBytes()));
        request.setSignatureFormat(AsymmetricSignatureFormat.DER);
        request.setSignatureType(AsymmetricSignatureType.ECDSA);

        VerifyAsymmetricSignatureResponse response = tested.verifySignature(request);
        assertFalse(response.isSignatureValid());
    }

}
