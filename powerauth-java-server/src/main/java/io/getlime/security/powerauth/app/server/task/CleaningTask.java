/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.task;

import io.getlime.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OperationServiceBehavior;
import io.getlime.security.powerauth.app.server.service.replay.ReplayPersistenceService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Task to clean expired operation, activation, and unique values.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Component
@AllArgsConstructor
@Slf4j
public class CleaningTask {

    private final ReplayPersistenceService replayPersistenceService;

    private final OperationServiceBehavior operationServiceBehavior;

    private final ActivationServiceBehavior activationServiceBehavior;

    @Scheduled(fixedRateString = "${powerauth.service.scheduled.job.uniqueValueCleanup:60000}")
    @SchedulerLock(
            name = "expireUniqueValuesTask",
            lockAtLeastFor = "#{T(java.lang.Math).round(${powerauth.service.scheduled.job.uniqueValueCleanup:60000} * 0.8)}")
    public void deleteExpiredUniqueValues() {
        LockAssert.assertLocked();
        logger.debug("Calling scheduled expiration of unique values");
        replayPersistenceService.deleteExpiredUniqueValues();
    }

    @Scheduled(fixedRateString = "${powerauth.service.scheduled.job.operationCleanup:5000}")
    @SchedulerLock(
            name = "expireOperationsTask",
            lockAtLeastFor = "#{T(java.lang.Math).round(${powerauth.service.scheduled.job.operationCleanup:5000} * 0.8)}")
    public void expireOperations() {
        LockAssert.assertLocked();
        logger.debug("Calling scheduled expiration of operations");
        operationServiceBehavior.expireOperations();
    }

    @Scheduled(fixedRateString = "${powerauth.service.scheduled.job.activationsCleanup:5000}")
    @SchedulerLock(
            name = "expireActivationsTask",
            lockAtLeastFor = "#{T(java.lang.Math).round(${powerauth.service.scheduled.job.activationsCleanup:5000} * 0.8)}")
    public void expireActivations() {
        LockAssert.assertLocked();
        logger.debug("Calling scheduled expiration of activations");
        activationServiceBehavior.expireActivations();
    }

}
