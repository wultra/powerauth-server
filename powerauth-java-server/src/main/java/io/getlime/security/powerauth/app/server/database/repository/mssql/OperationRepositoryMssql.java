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

package io.getlime.security.powerauth.app.server.database.repository.mssql;


import io.getlime.security.powerauth.app.server.configuration.conditions.IsMssqlCondition;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationRepository;
import org.springframework.context.annotation.Conditional;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Database repository for the operations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Repository
@Conditional(IsMssqlCondition.class)
public interface OperationRepositoryMssql extends OperationRepository {

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

}
