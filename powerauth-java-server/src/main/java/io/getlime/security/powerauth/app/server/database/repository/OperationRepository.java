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
 * @implSpec Oracle does not support {@code DISTINCT} on {@code CLOB} so subselects have to be used.
 */
@Repository
public interface OperationRepository extends CrudRepository<OperationEntity, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT o FROM OperationEntity o WHERE o.id = :operationId")
    Optional<OperationEntity> findOperationWithLock(String operationId);

    /**
     * Find operation with given operation ID. This method is MSSQL-specific.
     * The operation is locked using stored procedure sp_getapplock in exclusive mode.
     * The lock is released automatically at the end of the transaction. Transaction isolation
     * level READ COMMITTED is used because the lock is pessimistic, optimistic locking would
     * cause an UPDATE conflict error. The stored procedure raises an error in case the lock
     * could not be acquired.
     *
     * @param operationId Operation ID
     * @return Operation with given ID
     */
    @Query(value = """
            BEGIN TRANSACTION;
            DECLARE @res INT
                EXEC @res = sp_getapplock 
                            @Resource = ?1,
                            @LockMode = 'Exclusive',
                            @LockOwner = 'Transaction',
                            @LockTimeout = 60000,
                            @DbPrincipal = 'public'
                IF @res NOT IN (0, 1)
                BEGIN
                    RAISERROR ('Unable to acquire operation lock, error %d, transaction count %d', 16, 1, @res, @@trancount)
                END 
                ELSE
                BEGIN
                    SELECT * FROM pa_operation WHERE id = ?1
                    COMMIT TRANSACTION;
                END
            """, nativeQuery = true)
    Optional<OperationEntity> findOperationWithLockMssql(String operationId);

    @Query("SELECT o FROM OperationEntity o WHERE o.id = :operationId")
    Optional<OperationEntity> findOperation(String operationId);

    @Query("""
            SELECT o FROM OperationEntity o WHERE o.id IN (SELECT o.id FROM OperationEntity o INNER JOIN o.applications a
            WHERE o.userId = :userId
            AND a.id in :applicationIds
            AND (:activationId IS NULL OR o.activationId IS NULL OR o.activationId = :activationId)
            AND (:activationFlags IS NULL OR o.activationFlag IS NULL OR o.activationFlag IN :activationFlags))
            ORDER BY o.timestampCreated DESC
            """)
    Stream<OperationEntity> findAllOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, final Pageable pageable);

    @Query("""
            SELECT o FROM OperationEntity o WHERE o.id IN (SELECT o.id FROM OperationEntity o INNER JOIN o.applications a
            WHERE o.userId = :userId
            AND a.id IN :applicationIds
            AND o.status = io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo.PENDING
            AND (:activationId IS NULL OR o.activationId IS NULL OR o.activationId = :activationId)
            AND (:activationFlags IS NULL OR o.activationFlag IS NULL OR o.activationFlag IN :activationFlags))
            ORDER BY o.timestampCreated DESC
            """)
    Stream<OperationEntity> findPendingOperationsForUser(String userId, List<String> applicationIds, String activationId, List<String> activationFlags, final Pageable pageable);

    @Query("""
            SELECT o FROM OperationEntity o WHERE o.id IN (SELECT o.id FROM OperationEntity o INNER JOIN o.applications a 
            WHERE o.externalId = :externalId
            AND a.id IN :applicationIds)
            ORDER BY o.timestampCreated DESC
            """)
    Stream<OperationEntity> findOperationsByExternalId(String externalId, List<String> applicationIds, final Pageable pageable);

    @Query("""
            SELECT o FROM OperationEntity o 
            WHERE o.timestampExpires < :timestamp
            AND o.status = io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo.PENDING
            """)
    Stream<OperationEntity> findExpiredPendingOperations(Date timestamp, Pageable pageable);

}
