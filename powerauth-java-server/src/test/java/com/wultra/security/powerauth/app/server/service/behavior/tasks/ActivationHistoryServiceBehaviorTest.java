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
 */
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

/**
 * Test for {@link ActivationHistoryServiceBehavior}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ActivationHistoryServiceBehaviorTest {

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private AuditingServiceBehavior audit;

    @InjectMocks
    private ActivationHistoryServiceBehavior tested;

    @Test
    void testLogAuditItem_additionalData() {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setApplication(new ApplicationEntity());
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setAdditionalData("""
                {"foo":"bar"}
                """);

        tested.logAuditItem(activation, "user1", "test");

        final ArgumentCaptor<AuditDetail> auditDetailCaptor = ArgumentCaptor.forClass(AuditDetail.class);

        verify(audit).log(eq(AuditLevel.INFO), any(), auditDetailCaptor.capture(), any(), any());

        final AuditDetail capturedAuditDetail = auditDetailCaptor.getValue();

        assertThat(capturedAuditDetail.getType()).isEqualTo("activation");
        assertThat(capturedAuditDetail.getParam().get("additionalData")).isEqualTo(Map.of("foo", "bar"));
    }

    @Test
    void testLogAuditItem_additionalData_invalidJson() {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setApplication(new ApplicationEntity());
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setAdditionalData("invalid json");

        tested.logAuditItem(activation, "user1", "test");

        final ArgumentCaptor<AuditDetail> auditDetailCaptor = ArgumentCaptor.forClass(AuditDetail.class);

        verify(audit).log(eq(AuditLevel.INFO), any(), auditDetailCaptor.capture(), any(), any());

        final AuditDetail capturedAuditDetail = auditDetailCaptor.getValue();

        assertThat(capturedAuditDetail.getType()).isEqualTo("activation");
        assertThat(capturedAuditDetail.getParam().get("additionalData")).isNull();
    }
}
