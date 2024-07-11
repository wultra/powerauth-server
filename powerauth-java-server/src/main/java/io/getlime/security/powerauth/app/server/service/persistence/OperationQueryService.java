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

import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service for operation queries with pessimistic locking.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class OperationQueryService {

    private static final Logger logger = LoggerFactory.getLogger(OperationQueryService.class);

    private final OperationRepository operationRepository;
    private final DataSourceProperties dataSourceProperties;

    @Autowired
    public OperationQueryService(OperationRepository operationRepository, DataSourceProperties dataSourceProperties) {
        this.operationRepository = operationRepository;
        this.dataSourceProperties = dataSourceProperties;
    }

    /**
     * Find an operation and lock it for an update.
     * @param operationId Activation ID.
     * @return Locked operation, if present.
     */
    public Optional<OperationEntity> findOperationForUpdate(String operationId) {
        try {
            if (dataSourceProperties.getUrl().contains("jdbc:sqlserver")) {
                // Find and lock operation using stored procedure for MSSQL
                return operationRepository.findOperationWithLockMSSQL(operationId);
            }
            return operationRepository.findOperationWithLock(operationId);
        } catch (Exception ex) {
            logger.error("Operation query failed", ex);
            return Optional.empty();
        }
    }
}