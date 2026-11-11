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

import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Test for {@link VaultUnlockServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class VaultUnlockServiceBehaviorTest {

    @Test
    void testBuildAuditInfoReturnsMutableList() throws Exception {
        final VaultUnlockServiceBehavior behavior = new VaultUnlockServiceBehavior(
                null, null, null, null, null, null, null, null, null);

        final Method buildAuditInfo = VaultUnlockServiceBehavior.class.getDeclaredMethod("buildAuditInfo", String.class);
        buildAuditInfo.setAccessible(true);

        @SuppressWarnings("unchecked")
        final List<KeyValue> auditInfo = (List<KeyValue>) buildAuditInfo.invoke(behavior, "DISPLAY_DATA");

        assertThat(auditInfo).singleElement().satisfies(entry -> {
            assertThat(entry.getKey()).isEqualTo(AdditionalInformation.Key.VAULT_UNLOCKED_REASON);
            assertThat(entry.getValue()).isEqualTo("DISPLAY_DATA");
        });

        // The list is later mutated downstream via getAdditionalInfo().add(...), so it must be mutable.
        final KeyValue extra = new KeyValue();
        extra.setKey(AdditionalInformation.Key.BLOCKED_REASON);
        extra.setValue(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
        assertThatCode(() -> auditInfo.add(extra)).doesNotThrowAnyException();
        assertThat(auditInfo).hasSize(2);
    }

    @Test
    void testBuildAuditInfoUsesDefaultReasonWhenNull() throws Exception {
        final VaultUnlockServiceBehavior behavior = new VaultUnlockServiceBehavior(
                null, null, null, null, null, null, null, null, null);

        final Method buildAuditInfo = VaultUnlockServiceBehavior.class.getDeclaredMethod("buildAuditInfo", String.class);
        buildAuditInfo.setAccessible(true);

        @SuppressWarnings("unchecked")
        final List<KeyValue> auditInfo = (List<KeyValue>) buildAuditInfo.invoke(behavior, (String) null);

        assertThat(auditInfo).singleElement().satisfies(entry ->
                assertThat(entry.getValue()).isEqualTo(AdditionalInformation.Reason.VAULT_UNLOCKED_REASON_NOT_SPECIFIED));
    }

}
