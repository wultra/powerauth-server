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
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import javax.persistence.LockModeType;
import java.util.Date;
import java.util.Optional;

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

    @Query("SELECT o FROM OperationEntity o WHERE o.userId = :userId AND o.applicationId = :applicationId ORDER BY o.timestampCreated DESC")
    Iterable<OperationEntity> findAllOperationsForUser(String userId, Long applicationId);

    @Query("SELECT o FROM OperationEntity o " +
            "WHERE o.userId = :userId AND o.applicationId = :applicationId AND o.status = io.getlime.security.powerauth.app.server.database.model.OperationStatusDo.PENDING " +
            "ORDER BY o.timestampCreated DESC")
    Iterable<OperationEntity> findPendingOperationsForUser(String userId, Long applicationId);

    @Query("SELECT o FROM OperationEntity o WHERE o.externalId = :externalId AND o.applicationId = :applicationId ORDER BY o.timestampCreated DESC")
    Iterable<OperationEntity> findOperationsByExternalId(String externalId, Long applicationId);

    @Query("SELECT o FROM OperationEntity o " +
            "WHERE o.timestampExpires < :timestamp AND o.status = io.getlime.security.powerauth.app.server.database.model.OperationStatusDo.PENDING " +
            "ORDER BY o.timestampCreated")
    Iterable<OperationEntity> findExpiredPendingOperations(Date timestamp);

}
