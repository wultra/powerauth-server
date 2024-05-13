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

import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.UniqueValueEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.database.repository.UniqueValueRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Date;

/**
 * Service for checking unique cryptography values to prevent replay attacks.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ReplayPersistenceService {

    private final UniqueValueRepository uniqueValueRepository;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    /**
     * Service constructor.
     * @param uniqueValueRepository Unique value repository.
     * @param powerAuthServiceConfiguration PowerAuth service configuration.
     */
    @Autowired
    public ReplayPersistenceService(UniqueValueRepository uniqueValueRepository, PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.uniqueValueRepository = uniqueValueRepository;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
    }

    /**
     * Check whether unique value exists in the database.
     * @param uniqueValue Unique value to check.
     * @return Whether unique value exists.
     */
    public boolean uniqueValueExists(final String uniqueValue) {
        return uniqueValueRepository.findById(uniqueValue).isPresent();
    }

    /**
     * Persist a unique value into the database.
     * @param type Unique value type.
     * @param uniqueValue Unique value.
     * @return Whether unique value was added successfully.
     */
    public boolean persistUniqueValue(final UniqueValueType type, final String uniqueValue) {
        final Instant expiration = Instant.now().plus(powerAuthServiceConfiguration.getRequestExpiration());
        final UniqueValueEntity uniqueVal = new UniqueValueEntity();
        uniqueVal.setType(type);
        uniqueVal.setUniqueValue(uniqueValue);
        uniqueVal.setTimestampExpires(Date.from(expiration));
        try {
            uniqueValueRepository.save(uniqueVal);
            return true;
        } catch (Exception ex) {
            logger.warn("Could not persist unique value: " + uniqueValue, ex);
            return false;
        }
    }

    /**
     * Remove expired unique values in the database.
     */
    @Transactional
    public void deleteExpiredUniqueValues() {
        final int expiredCount = uniqueValueRepository.deleteExpiredValues(new Date());
        logger.debug("Removed {} expired unique values", expiredCount);
    }
}
