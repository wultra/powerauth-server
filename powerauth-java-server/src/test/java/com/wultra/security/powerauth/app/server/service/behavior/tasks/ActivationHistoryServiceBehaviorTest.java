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

import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.AuditingServiceBehavior;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

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
@SpringBootTest
@ActiveProfiles("test")
class ActivationHistoryServiceBehaviorTest {

    @MockitoBean
    private AuditingServiceBehavior audit;

    @Autowired
    private ActivationHistoryServiceBehavior tested;

    @Test
    void testLogAuditItem_additionalData() {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setUserId("internal-user-id");
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
        assertThat(capturedAuditDetail.getSubjectId()).isEqualTo("internal-user-id");
    }

    @Test
    void testLogAuditItem_additionalData_invalidJson() {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setUserId("internal-user-id");
        activation.setApplication(new ApplicationEntity());
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setAdditionalData("invalid json");

        tested.logAuditItem(activation, "user1", "test");

        final ArgumentCaptor<AuditDetail> auditDetailCaptor = ArgumentCaptor.forClass(AuditDetail.class);

        verify(audit).log(eq(AuditLevel.INFO), any(), auditDetailCaptor.capture(), any(), any());

        final AuditDetail capturedAuditDetail = auditDetailCaptor.getValue();

        assertThat(capturedAuditDetail.getType()).isEqualTo("activation");
        assertThat(capturedAuditDetail.getParam().get("additionalData")).isNull();
        assertThat(capturedAuditDetail.getSubjectId()).isEqualTo("internal-user-id");
    }
}
