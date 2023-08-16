/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.service.replay;

import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service for expiring database records related to prevention against replay attacks.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ReplayExpirationService {

    private final ReplayPersistenceService replayPersistenceService;

    /**
     * Service constructor.
     * @param replayPersistenceService Replay persistence service.
     */
    @Autowired
    public ReplayExpirationService(ReplayPersistenceService replayPersistenceService) {
        this.replayPersistenceService = replayPersistenceService;
    }

    @Scheduled(fixedRateString = "${powerauth.service.scheduled.job.uniqueValueCleanup:PT1M}")
    @SchedulerLock(name = "expireUniqueValuesTask")
    @Transactional
    public void processExpirations() {
        replayPersistenceService.deleteExpiredUniqueValues();
    }
}
