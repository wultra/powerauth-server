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
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.stereotype.Service;

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
    private final DataSourceProperties dataSourceProperties;

    @Autowired
    public ActivationQueryService(ActivationRepository activationRepository, DataSourceProperties dataSourceProperties) {
        this.activationRepository = activationRepository;
        this.dataSourceProperties = dataSourceProperties;
    }

    /**
     * Find an activation and lock it for an update.
     * @param activationId Activation ID.
     * @return Locked activation, if present.
     */
    public Optional<ActivationRecordEntity> findActivationForUpdate(String activationId) {
        try {
            if (dataSourceProperties.getUrl().contains("jdbc:sqlserver")) {
                // Find and lock activation using stored procedure for MSSQL
                return activationRepository.findActivationWithLockMSSQL(activationId);
            }
            return activationRepository.findActivationWithLock(activationId);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }
}