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

import io.getlime.security.powerauth.app.server.configuration.conditions.IsMssqlCondition;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.repository.mssql.OperationRepositoryMssql;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Service for operation queries with pessimistic locking.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Conditional(IsMssqlCondition.class)
public class OperationQueryServiceMssql implements OperationQueryService {

    private static final Logger logger = LoggerFactory.getLogger(OperationQueryServiceMssql.class);

    private final OperationRepositoryMssql operationRepository;

    @Autowired
    public OperationQueryServiceMssql(OperationRepositoryMssql operationRepository) {
        this.operationRepository = operationRepository;
    }

    /**
     * Find an operation and lock it for an update.
     * @param operationId Activation ID.
     * @return Locked operation, if present.
     */
    public Optional<OperationEntity> findOperationForUpdate(String operationId) {
        try {
            return operationRepository.findOperationWithLockMssql(operationId);
        } catch (Exception ex) {
            logger.error("Operation query failed", ex);
            return Optional.empty();
        }
    }

    @Override
    public Optional<OperationEntity> findOperationWithoutLock(String operationId) {
        try {
            return operationRepository.findOperationWithoutLockMssql(operationId);
        } catch (Exception ex) {
            logger.error("Operation query failed", ex);
            return Optional.empty();
        }
    }

    @Override
    public Stream<OperationEntity> findAllOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, Pageable pageable) {
        try {
            return operationRepository.findAllOperationsForUserMssql(userId, applicationIds, activationId, activationFlags, pageable);
        } catch (Exception ex) {
            logger.error("Operation query failed", ex);
            return Stream.empty();
        }
    }

    @Override
    public Stream<OperationEntity> findPendingOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, Pageable pageable) {
        try {
            return operationRepository.findAllOperationsForUserMssql(userId, applicationIds, activationId, activationFlags, pageable);
        } catch (Exception ex) {
            logger.error("Operation query failed", ex);
            return Stream.empty();
        }
    }

    @Override
    public Stream<OperationEntity> findOperationsByExternalId(String externalId, List<String> applicationIds, Pageable pageable) {
        try {
            return operationRepository.findOperationsByExternalIdMssql(externalId, applicationIds, pageable);
        } catch (Exception ex) {
            logger.error("Operation query failed", ex);
            return Stream.empty();
        }
    }

    @Override
    public Stream<OperationEntity> findExpiredPendingOperations(Date timestamp, Pageable pageable) {
        try {
            return operationRepository.findExpiredPendingOperationsMssql(timestamp, pageable);
        } catch (Exception ex) {
            logger.error("Operation query failed", ex);
            return Stream.empty();
        }
    }

}