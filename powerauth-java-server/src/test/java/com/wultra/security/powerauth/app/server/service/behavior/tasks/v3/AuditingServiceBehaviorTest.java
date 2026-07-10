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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.core.audit.base.Audit;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.app.server.converter.KeyValueMapConverter;
import com.wultra.security.powerauth.app.server.database.model.PowerAuthAuthenticationCodeMetadata;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.SignatureEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.database.repository.SignatureAuditRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.authentication.v3.SignatureData;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.request.SignatureAuditRequest;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test for {@link AuditingServiceBehavior}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class AuditingServiceBehaviorTest {

    @Mock
    private Audit audit;

    @Mock
    private KeyValueMapConverter keyValueMapConverter;

    @Mock
    private ActivationRepository activationRepository;

    @Mock
    private SignatureAuditRepository signatureAuditRepository;

    @InjectMocks
    private AuditingServiceBehavior tested;

    @Test
    void testLogSignatureAuditRecord() throws GenericServiceException {
        final AuditingServiceBehavior.ActivationRecordDto activation = AuditingServiceBehavior.ActivationRecordDto.builder()
                .activationId("act123")
                .applicationId("app456")
                .counter(1L)
                .userId("user789")
                .ctrDataBase64("Y3RyRGF0YQ==")
                .activationStatus(ActivationStatus.ACTIVE)
                .build();

        final byte[] data = Base64.getDecoder().decode("UE9TVCZMM0JoTDNOcFoyNWhkSFZ5WlM5MllXeHBaR0YwWlE9PSYyaVR6Ry9CMzVRSmY3SHhaZmNseUZnPT0mUVd4c0lIbHZkWElnWW1GelpTQmhjbVVnWW1Wc2IyNW5JSFJ2SUhWeklRPT0mbzk3MGdVQkx2d0NUZGJJT1BrWjBsdz09");
        final SignatureData signatureData = new SignatureData(data, "39319618-09892741", AuthenticationCodeConfiguration.decimal(), "3.0", List.of(), 3);

        final SignatureType signatureType = SignatureType.POSSESSION;

        tested.logSignatureAuditRecord(activation, signatureData, signatureType, true, 1, "Test note", new java.util.Date());

        final ArgumentCaptor<AuditDetail> detailCaptor =
                org.mockito.ArgumentCaptor.forClass(AuditDetail.class);

        verify(audit).log(
                eq("Signature validation completed: {}, activation ID: {}, user ID: {}"),
                eq(AuditLevel.INFO),
                detailCaptor.capture(),
                eq("SUCCESS"),
                eq("act123"),
                eq("user789")
        );

        final AuditDetail auditDetail = detailCaptor.getValue();
        final Map<String, Object> params = auditDetail.getParam();

        assertEquals("act123", params.get("activationId"));
        assertEquals("app456", params.get("applicationId"));
        assertEquals("user789", params.get("userId"));
        assertEquals(true, params.get("valid"));
        assertEquals(1L, params.get("counter"));
        assertEquals("Y3RyRGF0YQ==", params.get("counterData"));
        assertEquals(ActivationStatus.ACTIVE, params.get("activationStatus"));
        assertEquals("Test note", params.get("note"));

        final PowerAuthAuthenticationCodeMetadata signatureMetadata = new PowerAuthAuthenticationCodeMetadata();
        signatureMetadata.setAuthDataMethod("POST");
        signatureMetadata.setAuthDataUriId("/pa/signature/validate");
        assertEquals(signatureMetadata, params.get("signatureMetadata"));

        assertEquals("user789", auditDetail.getSubjectId());

        final ArgumentCaptor<SignatureEntity> entityCaptor = ArgumentCaptor.forClass(SignatureEntity.class);
        verify(signatureAuditRepository).save(entityCaptor.capture());
        final SignatureEntity saved = entityCaptor.getValue();
        assertEquals("39319618-09892741", saved.getSignature());
        assertNull(saved.getSignatureAsymmetric());
        assertEquals("39319618-09892741", saved.getAuditedSignature());
    }

    /**
     * Test the signature audit log returns also no longer supported signature type.
     */
    @Test
    void testGetSignatureAuditLog_unsupportedSignatureType() throws Exception {
        final SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId("user789");

        final ActivationRecordEntity activationRecordEntity = new ActivationRecordEntity();
        final ApplicationEntity applicationEntity = new ApplicationEntity();
        applicationEntity.setId("app456");
        activationRecordEntity.setApplication(applicationEntity);
        activationRecordEntity.setActivationId("act123");
        activationRecordEntity.setUserId("user789");

        final SignatureEntity signatureEntity = new SignatureEntity();
        signatureEntity.setId(1L);
        signatureEntity.setSignatureType("POSSESSION_KNOWLEDGE_BIOMETRY");
        signatureEntity.setActivationCounter(0L);
        signatureEntity.setActivationStatus(ActivationStatus.ACTIVE);
        signatureEntity.setValid(true);
        signatureEntity.setVersion(3);
        signatureEntity.setActivation(activationRecordEntity);

        when(signatureAuditRepository.findSignatureAuditRecordsForUser(any(), any(), any()))
                .thenReturn(List.of(signatureEntity));

        assertEquals("POSSESSION_KNOWLEDGE_BIOMETRY", tested.getSignatureAuditLog(request).getItems().get(0).getSignatureType());
    }

    /**
     * Test that an asymmetric signature audit record stores the signature in the {@code signatureAsymmetric}
     * (CLOB) column and leaves the {@code signature} column empty.
     */
    @Test
    void testLogAsymmetricSignatureAuditRecord_storedInSignatureAsymmetric() {
        final ApplicationEntity applicationEntity = new ApplicationEntity();
        applicationEntity.setId("app456");

        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setApplication(applicationEntity);
        activation.setActivationId("act123");
        activation.setUserId("user789");
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setCounter(0L);
        activation.setCtrDataBase64("Y3RyRGF0YQ==");
        activation.setVersion(3);

        final String signatureBase64 = Base64.getEncoder().encodeToString(new byte[3000]);

        tested.logAsymmetricSignatureAuditRecord(activation, "ZGF0YQ==", signatureBase64,
                "ECDSA_P256", "DER", true, "asymmetric_signature_ok", new java.util.Date());

        final ArgumentCaptor<SignatureEntity> entityCaptor = ArgumentCaptor.forClass(SignatureEntity.class);
        verify(signatureAuditRepository).save(entityCaptor.capture());

        final SignatureEntity saved = entityCaptor.getValue();
        assertNull(saved.getSignature());
        assertEquals(signatureBase64, saved.getSignatureAsymmetric());
        assertEquals(signatureBase64, saved.getAuditedSignature());
        assertEquals("ASYMMETRIC", saved.getSignatureType());
        assertEquals("ECDSA_P256", saved.getSignatureAlgorithm());
        assertEquals("DER", saved.getSignatureFormat());
    }

    /**
     * Test that the signature audit log API surfaces the asymmetric signature value for records that store it
     * in the {@code signatureAsymmetric} column and leave {@code signature} null.
     */
    @Test
    void testGetSignatureAuditLog_surfacesAsymmetricSignature() throws Exception {
        final SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId("user789");

        final ActivationRecordEntity activationRecordEntity = new ActivationRecordEntity();
        final ApplicationEntity applicationEntity = new ApplicationEntity();
        applicationEntity.setId("app456");
        activationRecordEntity.setApplication(applicationEntity);
        activationRecordEntity.setActivationId("act123");
        activationRecordEntity.setUserId("user789");

        final String signatureBase64 = Base64.getEncoder().encodeToString(new byte[3000]);

        final SignatureEntity signatureEntity = new SignatureEntity();
        signatureEntity.setId(1L);
        signatureEntity.setSignatureType("ASYMMETRIC");
        signatureEntity.setSignatureAsymmetric(signatureBase64);
        signatureEntity.setActivationCounter(0L);
        signatureEntity.setActivationStatus(ActivationStatus.ACTIVE);
        signatureEntity.setValid(true);
        signatureEntity.setVersion(3);
        signatureEntity.setActivation(activationRecordEntity);

        when(signatureAuditRepository.findSignatureAuditRecordsForUser(any(), any(), any()))
                .thenReturn(List.of(signatureEntity));

        assertEquals(signatureBase64, tested.getSignatureAuditLog(request).getItems().get(0).getSignature());
    }
}
