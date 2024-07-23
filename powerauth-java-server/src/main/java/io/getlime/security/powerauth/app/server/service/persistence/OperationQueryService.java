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
import org.springframework.data.domain.Pageable;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Service for operation queries with pessimistic locking.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface OperationQueryService {

    /**
     * Find an operation and lock it using a pessimistic lock for an update (may be database specific).
     * @param operationId Activation ID.
     * @return Locked operation, if present.
     */
    Optional<OperationEntity> findOperationForUpdate(String operationId);

    /**
     * Find an operation without locking it.
     * @param operationId Activation ID.
     * @return Locked operation, if present.
     */
    Optional<OperationEntity> findOperationWithoutLock(String operationId);

    /**
     * Find all operations with search criteria.
     * @param userId User identifier.
     * @param applicationIds Application identifiers.
     * @param activationId Activation identifier.
     * @param activationFlags Activation flags.
     * @param pageable Pageable.
     * @return Stream of operations.
     */
    Stream<OperationEntity> findAllOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, final Pageable pageable);

    /**
     * Find pending operations with search criteria.
     * @param userId User identifier.
     * @param applicationIds Application identifiers.
     * @param activationId Activation identifier.
     * @param activationFlags Activation flags.
     * @param pageable Pageable.
     * @return Stream of operations.
     */
    Stream<OperationEntity> findPendingOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, final Pageable pageable);

    /**
     * Find operations by an external identifier.
     * @param externalId External identifier.
     * @param applicationIds Application identifiers.
     * @param pageable Pageable.
     * @return Stream of operations.
     */
    Stream<OperationEntity> findOperationsByExternalId(String externalId, List<String> applicationIds, final Pageable pageable);

    /**
     * Find expired pending operations.
     * @param timestamp Timestamp.
     * @return Stream of operations.
     */
    Stream<OperationEntity> findExpiredPendingOperations(Date timestamp);

}