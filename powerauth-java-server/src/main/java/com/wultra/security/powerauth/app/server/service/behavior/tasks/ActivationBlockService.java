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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Service implementing the activation block feature. Encapsulates all logic related
 * to blocking and optionally resetting the time-bound block applied after the maximum number of
 * failed authentication attempts is reached.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ActivationBlockService {

    private static final long MAX_DATE_MILLISECONDS = 253_370_764_800_000L;

    /**
     * Minimal cryptography protocol version for which the temporary activation block feature applies.
     * Activations using an older protocol version are blocked permanently (legacy behavior).
     */
    private static final long MIN_PROTOCOL_VERSION_FOR_TEMPORARY_BLOCK = 4L;

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final CallbackUrlBehavior callbackUrlBehavior;
    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;

    /**
     * Apply a block to an activation that has reached the maximum number of failed authentication
     * attempts. The {@link ActivationStatus#BLOCKED} state and the {@code MAX_FAILED_ATTEMPTS} blocked reason
     * are set on the activation entity. When the temporary block feature is enabled, for v4 protocol version
     * the block is temporary. The block expiration timestamp is computed using the configured base period and multiplier:
     * <pre>{@code timestampBlockExpire = currentTimestamp + periodInMilliseconds * multiplier^(temporaryBlockCount-1)}</pre>
     * For v3 protocol version the block is always permanent.
     *
     * @param activation Activation to block.
     * @param currentTimestamp Current timestamp.
     */
    public void blockActivation(final ActivationRecordEntity activation, final Date currentTimestamp) throws GenericServiceException {
        // If the activation is already temporarily blocked and the block period has not elapsed yet, keep
        // the existing block in place.
        if (isTemporaryBlockActive(activation, currentTimestamp)) {
            logger.debug("Activation is already temporarily blocked, keeping the existing block, activation ID: {}, expires at: {}",
                    activation.getActivationId(), activation.getTimestampBlockExpire());
            return;
        }
        activation.setActivationStatus(ActivationStatus.BLOCKED);
        activation.setBlockedReason(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
        if (!isTemporaryBlockApplicable(activation)) {
            // Permanent block is used in case temporary block is not applicable
            activation.setTemporaryBlockCount(0L);
            activation.setTimestampBlockExpire(null);
            logger.info("Activation blocked permanently, activation ID: {}", activation.getActivationId());
            return;
        }
        final long nextBlockCount = activation.getTemporaryBlockCount() + 1L;
        activation.setTemporaryBlockCount(nextBlockCount);
        final long periodMs = computeBlockPeriodMillis(nextBlockCount);
        final long currentMs = currentTimestamp.getTime();
        if (periodMs > MAX_DATE_MILLISECONDS - currentMs) {
            activation.setTimestampBlockExpire(new Date(MAX_DATE_MILLISECONDS));
        } else {
            activation.setTimestampBlockExpire(new Date(currentMs + periodMs));
        }
        logger.info("Activation blocked temporarily, activation ID: {}, block #{}, expires at: {}",
                activation.getActivationId(), nextBlockCount, activation.getTimestampBlockExpire());
    }

    /**
     * Reset the temporary block state on a successful authentication. Clears the block counter on the entity.
     *
     * @param activation Activation to reset the block state.
     */
    public void resetTemporaryBlockState(final ActivationRecordEntity activation) {
        if (activation.getTemporaryBlockCount() > 0) {
            activation.setTemporaryBlockCount(0L);
            activation.setTimestampBlockExpire(null);
        }
    }

    /**
     * Remove a temporary block on the provided activation if it has expired. The activation is restored
     * to {@link ActivationStatus#ACTIVE} state and its {@code blockedReason} and {@code timestampBlockExpire}
     * are cleared. The {@code failedAttempts} counter is decreased by 1 (so that the user has one last
     * authentication attempt available before being blocked again). The {@code temporaryBlockCount} is
     * preserved so that the next consecutive block uses a longer period. The change is logged via
     * {@link ActivationHistoryServiceBehavior} and listeners are notified via {@link CallbackUrlBehavior}.
     *
     * <p>Has no effect when the activation is not temporarily blocked, is blocked for a different reason,
     * or its block timestamp is still in the future.
     *
     * @param activationToCheck Activation to evaluate.
     * @param currentTimestamp  Current timestamp.
     */
    public void expireTemporaryBlockIfRequired(final ActivationRecordEntity activationToCheck, final Date currentTimestamp) {
        if (!isTemporaryBlockExpired(activationToCheck, currentTimestamp)) {
            return;
        }
        // Obtain the activation with a row lock and refresh its state from the database. The entity was loaded
        // earlier in this same transaction, so a locking query alone would return the cached instance with
        // stale in-memory state.
        final ActivationRecordEntity activation = activationQueryService
                .findActivationForUpdateRefreshed(activationToCheck.getActivationId())
                .orElse(null);
        if (activation == null) {
            logger.warn("Activation was removed while expiring temporary block, activation ID: {}", activationToCheck.getActivationId());
            return;
        }
        // Re-check the locked and refreshed activation to avoid race conditions
        if (!isTemporaryBlockExpired(activation, currentTimestamp)) {
            return;
        }
        activation.setActivationStatus(ActivationStatus.ACTIVE);
        activation.setBlockedReason(null);
        activation.setTimestampBlockExpire(null);
        // Leave one last authentication attempt available, so the user can recover by successful verification.
        // The temporary block counter is preserved so that the next failure is blocked for a longer period.
        activation.setFailedAttempts(Math.max(activation.getFailedAttempts() - 1L, 0L));
        logger.info("Temporary activation block expired, activation is ACTIVE, activation ID: {}", activation.getActivationId());
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, null, AdditionalInformation.Reason.TEMPORARY_BLOCK_EXPIRED);
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
    }

    /**
     * Check whether the temporary block feature applies for the given activation. The feature applies
     * only to activations using v4 cryptography protocol. The feature needs to be enabled, too.
     * @param activation Activation entity.
     * @return Whether temporary block is applicable.
     */
    private boolean isTemporaryBlockApplicable(final ActivationRecordEntity activation) {
        return powerAuthServiceConfiguration.isTemporaryBlockEnabled()
                && activation.getVersion() != null
                && activation.getVersion() >= MIN_PROTOCOL_VERSION_FOR_TEMPORARY_BLOCK;
    }

    /**
     * Check whether the activation is currently temporarily blocked because of reaching the maximum
     * number of failed attempts, and whether the temporary block period has already elapsed.
     * @param activation Activation entity.
     * @param currentTimestamp Current timestamp.
     * @return Whether the temporary block on the activation can be expired.
     */
    private static boolean isTemporaryBlockExpired(final ActivationRecordEntity activation, final Date currentTimestamp) {
        return activation.getActivationStatus() == ActivationStatus.BLOCKED
                && AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS.equals(activation.getBlockedReason())
                && activation.getTimestampBlockExpire() != null
                && !activation.getTimestampBlockExpire().after(currentTimestamp);
    }

    /**
     * Check whether the activation currently has a temporary block in effect (timer not elapsed yet).
     * @param activation Activation entity.
     * @param currentTimestamp Current timestamp.
     * @return Whether the activation is currently temporarily blocked.
     */
    private static boolean isTemporaryBlockActive(final ActivationRecordEntity activation, final Date currentTimestamp) {
        return activation.getActivationStatus() == ActivationStatus.BLOCKED
                && AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS.equals(activation.getBlockedReason())
                && activation.getTimestampBlockExpire() != null
                && activation.getTimestampBlockExpire().after(currentTimestamp);
    }

    /**
     * Compute temporary block period in milliseconds.
     * @param blockCount Current block count.
     * @return Temporary block period in milliseconds.
     * @throws GenericServiceException Thrown in case of server configuration error.
     */
    private long computeBlockPeriodMillis(final long blockCount) throws GenericServiceException {
        final long blockPeriodBase = powerAuthServiceConfiguration.getTemporaryBlockPeriodInMilliseconds();
        final int multiplier = powerAuthServiceConfiguration.getTemporaryBlockMultiplier();
        if (blockCount <= 0) {
            logger.error("Incorrect block count: {}", blockCount);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        // Compute blockPeriodBase * multiplier^(blockCount-1)
        long period = blockPeriodBase;
        for (long i = 1; i < blockCount; i++) {
            if (period > MAX_DATE_MILLISECONDS) {
                // Do not allow longer block period than the value MAX_DATE_MILLISECONDS
                period = MAX_DATE_MILLISECONDS;
                break;
            } else {
                period *= multiplier;
            }
        }
        return period;
    }

}
