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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
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

    private ActivationRecordEntity activation;
    private final byte[] dataToSign = "DataToSign".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        activation = new ActivationRecordEntity();
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setProtocol(ActivationProtocol.POWERAUTH);
        activation.setCryptoAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
    }

    @Test
    void signDataValid() throws Exception {
        String activationId = "78f184f2-c434-474f-971e-9c2d255faf8c";
        String dataBase64 = Base64.getEncoder().encodeToString(dataToSign);

        String signatureEcdsa = "MGUCMHSj/atLUNwJrM0q8+PTtvNPpftHSGX3ErcyCwqfqZ0Ia627POEla+gaAcALqdLGjAIxAMa19AkR63k4HItcvqDcOuhgKv+E5PFcWXF1dkpgNq7jjvBMM3G1jYt7dG+DsVF71Q==";
        String signatureMldsa = "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";

        when(activationQueryService.findActivationWithoutLock(activationId)).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.generateSignatureForActivation(eq(KeyType.ECDSA_P384), eq(dataToSign), eq(activation)))
                .thenReturn(Base64.getDecoder().decode(signatureEcdsa));
        when(cryptographyService.generateSignatureForActivation(eq(KeyType.MLDSA_65), eq(dataToSign), eq(activation)))
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
        activation.setActivationStatus(ActivationStatus.REMOVED);
        when(activationQueryService.findActivationWithoutLock("78f184f2-c434-474f-971e-9c2d255faf8c")).thenReturn(Optional.of(activation));
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

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.ECDSA_P384), eq(dataBytes), eq(derSignature), eq(activation)))
                .thenReturn(true);

        VerifyAsymmetricSignatureResponse response = tested.verifySignature(request);
        assertTrue(response.isSignatureValid());
    }

    @Test
    void verifySignatureValid_Mldsa() throws Exception {
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

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activation));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.MLDSA_65), eq(dataBytes), eq(mldsaSignature), eq(activation)))
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
