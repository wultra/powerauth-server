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
package com.wultra.security.powerauth.app.server.service.persistence;

import com.wultra.security.powerauth.app.server.database.repository.TemporaryKeyRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

/**
 * Service for management of temporary keys
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class TemporaryKeyPersistenceService {

    private final TemporaryKeyRepository temporaryKeyRepository;

    @Transactional
    public void removeTemporaryKey(String temporaryKeyId) {
        temporaryKeyRepository.deleteById(temporaryKeyId);
    }

    // Tasks for scheduling
    @Transactional
    public void expireTemporaryKeys() {
        final Date currentTimestamp = new Date();
        final int expiredCount = temporaryKeyRepository.deleteExpiredKeys(currentTimestamp);
        logger.debug("Removed {} expired temporary keys", expiredCount);
    }

}
