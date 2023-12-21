/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.database.repository;


import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Database repository for the operations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Repository
public interface OperationRepository extends CrudRepository<OperationEntity, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT o FROM OperationEntity o WHERE o.id = :operationId")
    Optional<OperationEntity> findOperationWithLock(String operationId);

    @Query("SELECT o FROM OperationEntity o WHERE o.id = :operationId")
    Optional<OperationEntity> findOperation(String operationId);

    @Query("""
       SELECT DISTINCT o FROM OperationEntity o INNER JOIN o.applications a
       WHERE o.userId = :userId AND a.id in :applicationIds
       AND (:activationId IS NULL OR o.activationId = :activationId OR o.activationId IS NULL)
       AND (:activationFlags IS NULL OR o.activationFlag IN :activationFlags OR o.activationFlag IS NULL)
       ORDER BY o.timestampCreated DESC
       """)
    Stream<OperationEntity> findAllOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, final Pageable pageable);

    @Query("""
       SELECT DISTINCT o FROM OperationEntity o INNER JOIN o.applications a
       WHERE o.userId = :userId AND a.id IN :applicationIds
       AND o.status = io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo.PENDING
       AND (:activationId IS NULL OR o.activationId = :activationId OR o.activationId IS NULL)
       AND (:activationFlags IS NULL OR o.activationFlag IN :activationFlags OR o.activationFlag IS NULL)
       ORDER BY o.timestampCreated DESC
       """)
    Stream<OperationEntity> findPendingOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, final Pageable pageable);

    @Query("SELECT DISTINCT o FROM OperationEntity o INNER JOIN o.applications a WHERE o.externalId = :externalId AND a.id IN :applicationIds ORDER BY o.timestampCreated DESC")
    Stream<OperationEntity> findOperationsByExternalId(String externalId, List<String> applicationIds, final Pageable pageable);

    @Query("SELECT DISTINCT o FROM OperationEntity o " +
            "WHERE o.timestampExpires < :timestamp AND o.status = io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo.PENDING " +
            "ORDER BY o.timestampCreated")
    Stream<OperationEntity> findExpiredPendingOperations(Date timestamp);

}
