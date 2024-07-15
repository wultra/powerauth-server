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
 */
package io.getlime.security.powerauth.app.server.service.persistence;

import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Service for activation queries with pessimistic locking.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class ActivationQueryService {

    private static final Logger logger = LoggerFactory.getLogger(ActivationQueryService.class);

    private final ActivationRepository activationRepository;
    private final boolean isMssql;

    @Autowired
    public ActivationQueryService(ActivationRepository activationRepository, DataSourceProperties dataSourceProperties) {
        this.activationRepository = activationRepository;
        isMssql = dataSourceProperties.getUrl().contains("jdbc:sqlserver");
    }

    /**
     * Find an activation and lock it for an update.
     * @param activationId Activation ID.
     * @return Locked activation, if present.
     */
    public Optional<ActivationRecordEntity> findActivationForUpdate(String activationId) {
        try {
            if (isMssql) {
                // Find and lock activation using stored procedure for MSSQL
                return activationRepository.findActivationWithLockMssql(activationId);
            }
            return activationRepository.findActivationWithLock(activationId);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }

    /**
     * Find an activation by code without a lock. The record may be updated by another transaction.
     * @param applicationId Application ID.
     * @param activationCode Activation code.
     * @param states Allowed states.
     * @param currentTimestamp Current timestamp.
     * @return Activation, if present.
     */
    public Optional<ActivationRecordEntity> findActivationByCodeWithoutLock(String applicationId, String activationCode, Collection<ActivationStatus> states, Date currentTimestamp) {
        try {
            if (isMssql) {
                // Find and lock activation using stored procedure for MSSQL
                final List<Byte> statesBytes = states.stream().map(ActivationStatus::getByte).toList();
                return activationRepository.findActivationByCodeWithoutLockMssql(applicationId, activationCode, statesBytes, currentTimestamp);
            }
            return activationRepository.findActivationByCodeWithoutLock(applicationId, activationCode, states, currentTimestamp);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }
}