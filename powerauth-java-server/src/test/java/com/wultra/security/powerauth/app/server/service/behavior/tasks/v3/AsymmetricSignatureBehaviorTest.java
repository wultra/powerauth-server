/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.crypto.ProtocolVersionValidationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.enumeration.v3.ECDSASignatureFormat;
import com.wultra.security.powerauth.client.model.request.v3.VerifyECDSASignatureRequest;
import com.wultra.security.powerauth.client.model.response.v3.VerifyECDSASignatureResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test for {@link AsymmetricSignatureServiceBehavior} (V3) — focuses on signature audit wiring.
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

    @Mock
    private ProtocolVersionValidationService protocolVersionValidationService;

    @Mock
    private AuditingServiceBehavior auditingServiceBehavior;

    @InjectMocks
    private AsymmetricSignatureServiceBehavior tested;

    private ActivationRecordEntity activationV3;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        activationV3 = new ActivationRecordEntity();
        activationV3.setActivationStatus(ActivationStatus.ACTIVE);
        activationV3.setProtocol(ActivationProtocol.POWERAUTH);
        activationV3.setVersion(3);
    }

    @Test
    void verifyECDSASignatureValid_AuditedAsSuccess() throws Exception {
        final String encodedData = "RGF0YVRvU2lnbg==";
        final String base64Signature = "MEUCIQDYp+isOdLi9kcWDu9gZxHeUnFxbjqFpIGOSbd5lDpqngIgC/KP0rP5R1bu6pZRufD4vcqieq03I/lvN/7m4FpaI2A=";
        final byte[] derSignature = Base64.getDecoder().decode(base64Signature);
        final byte[] dataBytes = Base64.getDecoder().decode(encodedData);

        final VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId("8ff9ad77-2aff-4edf-8e27-8b08db8a6811");
        request.setData(encodedData);
        request.setSignature(base64Signature);
        request.setSignatureFormat(ECDSASignatureFormat.DER);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activationV3));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.ECDSA_P256), eq(dataBytes), eq(derSignature), eq(activationV3)))
                .thenReturn(true);

        final VerifyECDSASignatureResponse response = tested.verifyECDSASignature(request);

        assertTrue(response.isSignatureValid());
        verify(auditingServiceBehavior).logAsymmetricSignatureAuditRecord(
                eq(activationV3), eq(encodedData), eq(base64Signature),
                eq("ECDSA_P256"), eq("DER"), eq(true),
                eq("asymmetric_signature_ok"), any(Date.class));
    }

    @Test
    void verifyECDSASignatureInvalid_AuditedAsFailure() throws Exception {
        final String encodedData = "RGF0YVRvU2lnbg==";
        final String base64Signature = "MEUCIQDYp+isOdLi9kcWDu9gZxHeUnFxbjqFpIGOSbd5lDpqngIgC/KP0rP5R1bu6pZRufD4vcqieq03I/lvN/7m4FpaI2A=";
        final byte[] derSignature = Base64.getDecoder().decode(base64Signature);
        final byte[] dataBytes = Base64.getDecoder().decode(encodedData);

        final VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId("8ff9ad77-2aff-4edf-8e27-8b08db8a6811");
        request.setData(encodedData);
        request.setSignature(base64Signature);
        request.setSignatureFormat(ECDSASignatureFormat.DER);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activationV3));
        when(cryptographyServiceFactory.getService(any())).thenReturn(cryptographyService);
        when(cryptographyService.verifySignatureForActivation(eq(KeyType.ECDSA_P256), eq(dataBytes), eq(derSignature), eq(activationV3)))
                .thenReturn(false);

        final VerifyECDSASignatureResponse response = tested.verifyECDSASignature(request);

        assertFalse(response.isSignatureValid());
        verify(auditingServiceBehavior).logAsymmetricSignatureAuditRecord(
                eq(activationV3), eq(encodedData), eq(base64Signature),
                eq("ECDSA_P256"), eq("DER"), eq(false),
                eq("asymmetric_signature_does_not_match"), any(Date.class));
    }

    @Test
    void verifyECDSASignature_activationNotFound_NotAudited() throws GenericServiceException {
        final VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId("8ff9ad77-2aff-4edf-8e27-8b08db8a6811");
        request.setData(Base64.getEncoder().encodeToString("data".getBytes()));
        request.setSignature(Base64.getEncoder().encodeToString("sig".getBytes()));
        request.setSignatureFormat(ECDSASignatureFormat.DER);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.empty());

        final VerifyECDSASignatureResponse response = tested.verifyECDSASignature(request);

        assertFalse(response.isSignatureValid());
        verify(auditingServiceBehavior, never()).logAsymmetricSignatureAuditRecord(
                any(), anyString(), anyString(), anyString(), anyString(), eq(false), anyString(), any(Date.class));
    }

    @Test
    void verifyECDSASignature_invalidBase64_AuditedAsFormatInvalid() throws Exception {
        final VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId("8ff9ad77-2aff-4edf-8e27-8b08db8a6811");
        request.setData("@@@not-base64@@@");
        request.setSignature("####not-base64####");
        request.setSignatureFormat(ECDSASignatureFormat.DER);

        when(activationQueryService.findActivationWithoutLock(request.getActivationId())).thenReturn(Optional.of(activationV3));

        final VerifyECDSASignatureResponse response = tested.verifyECDSASignature(request);

        assertFalse(response.isSignatureValid());
        verify(auditingServiceBehavior).logAsymmetricSignatureAuditRecord(
                eq(activationV3), eq("@@@not-base64@@@"), eq("####not-base64####"),
                eq("ECDSA_P256"), eq("DER"), eq(false),
                eq("asymmetric_signature_format_invalid"), any(Date.class));
    }

}
