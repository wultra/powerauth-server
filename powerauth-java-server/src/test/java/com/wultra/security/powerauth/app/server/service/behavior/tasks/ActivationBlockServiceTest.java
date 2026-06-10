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
 */
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test for {@link ActivationBlockService}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ActivationBlockServiceTest {

    private static final long MAX_DATE_MILLISECONDS = 253_370_764_800_000L;
    private static final String ACTIVATION_ID = "e43a5dec-afea-4a10-a80b-b2183399f16b";

    @Mock
    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    @Mock
    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    @Mock
    private CallbackUrlBehavior callbackUrlBehavior;

    @Mock
    private ActivationQueryService activationQueryService;

    @InjectMocks
    private ActivationBlockService tested;

    // --- blockActivation --------------------------------------------------------------------------------------------

    @Test
    void testBlockActivation_permanentWhenFeatureDisabled() throws Exception {
        when(powerAuthServiceConfiguration.isTemporaryBlockEnabled()).thenReturn(false);
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 4, 5L, 0L, null);

        tested.blockActivation(activation, new Date());

        assertEquals(ActivationStatus.BLOCKED, activation.getActivationStatus());
        assertEquals(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, activation.getBlockedReason());
        assertEquals(0L, activation.getTemporaryBlockCount());
        assertNull(activation.getTimestampBlockExpire());
    }

    @Test
    void testBlockActivation_permanentForLegacyProtocolVersion() throws Exception {
        when(powerAuthServiceConfiguration.isTemporaryBlockEnabled()).thenReturn(true);
        // Protocol version 3 is below the minimum for the temporary block feature
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 3, 5L, 0L, null);

        tested.blockActivation(activation, new Date());

        assertEquals(ActivationStatus.BLOCKED, activation.getActivationStatus());
        assertEquals(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, activation.getBlockedReason());
        assertEquals(0L, activation.getTemporaryBlockCount());
        assertNull(activation.getTimestampBlockExpire());
    }

    @Test
    void testBlockActivation_temporaryFirstBlock() throws Exception {
        when(powerAuthServiceConfiguration.isTemporaryBlockEnabled()).thenReturn(true);
        when(powerAuthServiceConfiguration.getTemporaryBlockPeriodInMilliseconds()).thenReturn(1_000L);
        when(powerAuthServiceConfiguration.getTemporaryBlockMultiplier()).thenReturn(2);
        final Date now = new Date(1_000_000L);
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 4, 5L, 0L, null);

        tested.blockActivation(activation, now);

        assertEquals(ActivationStatus.BLOCKED, activation.getActivationStatus());
        assertEquals(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, activation.getBlockedReason());
        assertEquals(1L, activation.getTemporaryBlockCount());
        // First block uses the base period: now + 1000 ms
        assertEquals(now.getTime() + 1_000L, activation.getTimestampBlockExpire().getTime());
    }

    @Test
    void testBlockActivation_temporaryConsecutiveBlockUsesMultiplier() throws Exception {
        when(powerAuthServiceConfiguration.isTemporaryBlockEnabled()).thenReturn(true);
        when(powerAuthServiceConfiguration.getTemporaryBlockPeriodInMilliseconds()).thenReturn(1_000L);
        when(powerAuthServiceConfiguration.getTemporaryBlockMultiplier()).thenReturn(2);
        final Date now = new Date(1_000_000L);
        // Already blocked once (count = 1), this is the second block
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 4, 5L, 1L, null);

        tested.blockActivation(activation, now);

        assertEquals(2L, activation.getTemporaryBlockCount());
        // Second block: base * multiplier^(2-1) = 1000 * 2 = 2000 ms
        assertEquals(now.getTime() + 2_000L, activation.getTimestampBlockExpire().getTime());
    }

    @Test
    void testBlockActivation_temporaryBlockPeriodCappedAtMaxDate() throws Exception {
        when(powerAuthServiceConfiguration.isTemporaryBlockEnabled()).thenReturn(true);
        when(powerAuthServiceConfiguration.getTemporaryBlockPeriodInMilliseconds()).thenReturn(1_000L);
        when(powerAuthServiceConfiguration.getTemporaryBlockMultiplier()).thenReturn(2);
        final Date now = new Date(1_000_000L);
        // A very high consecutive block count drives the computed period beyond the maximum allowed date
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 4, 5L, 100L, null);

        tested.blockActivation(activation, now);

        assertEquals(101L, activation.getTemporaryBlockCount());
        assertEquals(MAX_DATE_MILLISECONDS, activation.getTimestampBlockExpire().getTime());
    }

    @Test
    void testBlockActivation_keepsExistingActiveTemporaryBlock() throws Exception {
        final Date now = new Date(1_000_000L);
        final Date existingExpire = new Date(now.getTime() + 60_000L);
        final ActivationRecordEntity activation = activation(ActivationStatus.BLOCKED,
                AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, 4, 5L, 1L, existingExpire);

        tested.blockActivation(activation, now);

        // Existing temporary block is preserved unchanged
        assertEquals(ActivationStatus.BLOCKED, activation.getActivationStatus());
        assertEquals(1L, activation.getTemporaryBlockCount());
        assertEquals(existingExpire, activation.getTimestampBlockExpire());
        verifyNoInteractions(activationHistoryServiceBehavior, callbackUrlBehavior, activationQueryService);
    }

    // --- resetTemporaryBlockState ----------------------------------------------------------------------------------

    @Test
    void testResetTemporaryBlockState_clearsCounterAndTimestamp() {
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 4, 0L, 3L, new Date());

        tested.resetTemporaryBlockState(activation);

        assertEquals(0L, activation.getTemporaryBlockCount());
        assertNull(activation.getTimestampBlockExpire());
    }

    @Test
    void testResetTemporaryBlockState_noOpWhenCounterZero() {
        final Date expire = new Date();
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 4, 0L, 0L, expire);

        tested.resetTemporaryBlockState(activation);

        assertEquals(0L, activation.getTemporaryBlockCount());
        // Timestamp is left untouched when there is no temporary block counter to reset
        assertEquals(expire, activation.getTimestampBlockExpire());
    }

    // --- expireTemporaryBlockIfRequired ----------------------------------------------------------------------------

    @Test
    void testExpireTemporaryBlock_skipsWhenNotExpired() {
        // Active activation is not a temporary block at all
        final ActivationRecordEntity activation = activation(ActivationStatus.ACTIVE, null, 4, 5L, 1L, null);

        tested.expireTemporaryBlockIfRequired(activation, new Date());

        verifyNoInteractions(activationQueryService, activationHistoryServiceBehavior, callbackUrlBehavior);
    }

    @Test
    void testExpireTemporaryBlock_skipsWhenBlockedForDifferentReason() {
        final Date now = new Date(1_000_000L);
        final Date pastExpire = new Date(now.getTime() - 1L);
        // Blocked for a reason other than reaching the maximum failed attempts (e.g. an administrative block)
        // must never be automatically unblocked, even if a (stale) past block-expire timestamp is present.
        final ActivationRecordEntity activation = activation(ActivationStatus.BLOCKED, "ADMIN_REQUEST", 4, 5L, 0L, pastExpire);

        tested.expireTemporaryBlockIfRequired(activation, now);

        verifyNoInteractions(activationQueryService, activationHistoryServiceBehavior, callbackUrlBehavior);
    }

    @Test
    void testExpireTemporaryBlock_unblocksWhenExpired() {
        final Date now = new Date(1_000_000L);
        final Date pastExpire = new Date(now.getTime() - 1L);
        final ActivationRecordEntity toCheck = activation(ActivationStatus.BLOCKED,
                AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, 4, 5L, 2L, pastExpire);
        final ActivationRecordEntity locked = activation(ActivationStatus.BLOCKED,
                AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, 4, 5L, 2L, pastExpire);
        when(activationQueryService.findActivationForUpdateRefreshed(ACTIVATION_ID)).thenReturn(Optional.of(locked));

        tested.expireTemporaryBlockIfRequired(toCheck, now);

        assertEquals(ActivationStatus.ACTIVE, locked.getActivationStatus());
        assertNull(locked.getBlockedReason());
        assertNull(locked.getTimestampBlockExpire());
        // One last attempt is made available, the temporary block counter is preserved
        assertEquals(4L, locked.getFailedAttempts());
        assertEquals(2L, locked.getTemporaryBlockCount());
        // The locked/refreshed entity is mutated, the stale passed-in entity is left untouched
        assertEquals(ActivationStatus.BLOCKED, toCheck.getActivationStatus());
        verify(activationHistoryServiceBehavior).saveActivationAndLogChange(locked, null, AdditionalInformation.Reason.TEMPORARY_BLOCK_EXPIRED);
        verify(callbackUrlBehavior).notifyCallbackListenersOnActivationChange(locked);
    }

    @Test
    void testExpireTemporaryBlock_failedAttemptsNotNegative() {
        final Date now = new Date(1_000_000L);
        final Date pastExpire = new Date(now.getTime() - 1L);
        final ActivationRecordEntity toCheck = activation(ActivationStatus.BLOCKED,
                AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, 4, 0L, 1L, pastExpire);
        final ActivationRecordEntity locked = activation(ActivationStatus.BLOCKED,
                AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, 4, 0L, 1L, pastExpire);
        when(activationQueryService.findActivationForUpdateRefreshed(ACTIVATION_ID)).thenReturn(Optional.of(locked));

        tested.expireTemporaryBlockIfRequired(toCheck, now);

        assertEquals(0L, locked.getFailedAttempts());
    }

    @Test
    void testExpireTemporaryBlock_skipsWhenRefreshedStateNoLongerExpired() {
        final Date now = new Date(1_000_000L);
        final Date pastExpire = new Date(now.getTime() - 1L);
        // The passed-in (stale) entity looks expired ...
        final ActivationRecordEntity toCheck = activation(ActivationStatus.BLOCKED,
                AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, 4, 5L, 1L, pastExpire);
        // ... but the locked-and-refreshed entity was already unblocked by a concurrent transaction
        final ActivationRecordEntity locked = activation(ActivationStatus.ACTIVE, null, 4, 4L, 1L, null);
        when(activationQueryService.findActivationForUpdateRefreshed(ACTIVATION_ID)).thenReturn(Optional.of(locked));

        tested.expireTemporaryBlockIfRequired(toCheck, now);

        // No second unblock is performed
        assertEquals(ActivationStatus.ACTIVE, locked.getActivationStatus());
        verifyNoInteractions(activationHistoryServiceBehavior, callbackUrlBehavior);
    }

    @Test
    void testExpireTemporaryBlock_skipsWhenActivationRemoved() {
        final Date now = new Date(1_000_000L);
        final Date pastExpire = new Date(now.getTime() - 1L);
        final ActivationRecordEntity toCheck = activation(ActivationStatus.BLOCKED,
                AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS, 4, 5L, 1L, pastExpire);
        when(activationQueryService.findActivationForUpdateRefreshed(ACTIVATION_ID)).thenReturn(Optional.empty());

        tested.expireTemporaryBlockIfRequired(toCheck, now);

        verifyNoInteractions(activationHistoryServiceBehavior, callbackUrlBehavior);
    }

    private static ActivationRecordEntity activation(final ActivationStatus status, final String blockedReason, final Integer version,
                                                     final Long failedAttempts, final Long temporaryBlockCount, final Date timestampBlockExpire) {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setActivationId(ACTIVATION_ID);
        activation.setActivationStatus(status);
        activation.setBlockedReason(blockedReason);
        activation.setVersion(version);
        activation.setFailedAttempts(failedAttempts);
        activation.setMaxFailedAttempts(5L);
        activation.setTemporaryBlockCount(temporaryBlockCount);
        activation.setTimestampBlockExpire(timestampBlockExpire);
        return activation;
    }

}

