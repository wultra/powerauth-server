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

import com.wultra.core.audit.base.Audit;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.security.powerauth.app.server.converter.KeyValueMapConverter;
import com.wultra.security.powerauth.app.server.database.model.PowerAuthAuthenticationCodeMetadata;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.database.repository.SignatureAuditRepository;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationData;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

/**
 * Test for {@link com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.AuditingServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
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
    void testLogSignatureAuditRecord() {
        final AuditingServiceBehavior.ActivationRecordDto activation = AuditingServiceBehavior.ActivationRecordDto.builder()
                .activationId("act123")
                .applicationId("app456")
                .counter(1L)
                .userId("user789")
                .ctrDataBase64("Y3RyRGF0YQ==")
                .activationStatus(com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus.ACTIVE)
                .build();

        final byte[] data = Base64.getDecoder().decode("UE9TVCZMM0JoTDJGMWRHZ3ZkbUZzYVdSaGRHVT0mMmlUekcvQjM1UUpmN0h4WmZjbHlGZz09JlFXeHNJSGx2ZFhJZ1ltVm5ZbVZuWW1WblltVm5ZbVZuSUhWdklHUnZidz09Jm85NzBnVUJMdndDVGRiSU9Qa1owbHc9PQ==");
        final AuthenticationData authData = new AuthenticationData(data, "39319618-09892741", AuthenticationCodeConfiguration.decimal(), "4.0", List.of());

        final AuthenticationCodeType authCodeType = AuthenticationCodeType.POSSESSION;

        tested.logAuthenticationAuditRecord(activation, authData, authCodeType, true, 1, "Test note", new java.util.Date());

        final ArgumentCaptor<AuditDetail> detailCaptor =
                ArgumentCaptor.forClass(AuditDetail.class);

        verify(audit).log(
                eq("Authentication validation completed: {}, activation ID: {}, user ID: {}"),
                eq(com.wultra.core.audit.base.model.AuditLevel.INFO),
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
        assertEquals(com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus.ACTIVE, params.get("activationStatus"));
        assertEquals("Test note", params.get("note"));

        final PowerAuthAuthenticationCodeMetadata authMetadata = new PowerAuthAuthenticationCodeMetadata();
        authMetadata.setAuthDataMethod("POST");
        authMetadata.setAuthDataUriId("/pa/auth/validate");
        assertEquals(authMetadata, params.get("authenticationMetadata"));
    }
}