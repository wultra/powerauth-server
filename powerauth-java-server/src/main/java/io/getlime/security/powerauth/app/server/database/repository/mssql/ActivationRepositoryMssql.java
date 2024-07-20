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

import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Date;
import java.util.Optional;

/**
 * Activation repository, specifics for MSSQL.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Repository
public interface ActivationRepositoryMssql extends ActivationRepository {

    /**
     * Find activation with given activation ID. This method is MSSQL-specific.
     * The activation is locked using stored procedure sp_getapplock in exclusive mode.
     * The lock is released automatically at the end of the outermost transaction.
     * Transaction isolation level READ COMMITTED is used because the lock is pessimistic.
     * The stored procedure raises an error in case the lock
     * could not be acquired.
     *
     * @param activationId Activation ID
     * @return Activation with given ID
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
                    RAISERROR ('Unable to acquire activation lock, error %d, transaction count %d', 16, 1, @res, @@trancount)
                END 
                ELSE
                BEGIN
                    SELECT * FROM pa_activation WHERE activation_id = ?1
                    COMMIT TRANSACTION;
                END
            """, nativeQuery = true)
    Optional<ActivationRecordEntity> findActivationWithLockMssql(String activationId);

    /**
     * Find the first activation associated with given application by the activation code.
     * Filter the results by activation state and make sure to apply activation time window.
     * <p>
     * Native query contains a workaround for MSSQL which avoids deadlock on activations by avoiding locking data.
     * The data needs to be locked later by calling findActivationWithLockMssql().
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param applicationId     Application ID
     * @param activationCode    Activation code
     * @param states            Allowed activation states
     * @param currentTimestamp  Current timestamp
     * @return Activation matching the search criteria or null if not found
     */
    @Query(value = "SELECT a.* FROM pa_activation a WITH (NOLOCK) JOIN pa_application app WITH (NOLOCK) ON app.id = a.application_id WHERE app.name = :applicationId AND a.activation_code = :activationCode AND a.activation_status IN (:states) AND a.timestamp_activation_expire > :currentTimestamp", nativeQuery = true)
    Optional<ActivationRecordEntity> findActivationByCodeWithoutLockMssql(String applicationId, String activationCode, Collection<Byte> states, Date currentTimestamp);

}
