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
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.stream.Stream;

/**
 * Activation repository, specifics for MSSQL.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Repository
public interface ActivationRepositoryMssql {

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
     * @param applicationId    Application ID
     * @param activationCode   Activation code
     * @param states           Allowed activation states
     * @param currentTimestamp Current timestamp
     * @return Activation matching the search criteria or null if not found
     */
    @Query(value = "SELECT a.* FROM pa_activation a WITH (NOLOCK) JOIN pa_application app WITH (NOLOCK) ON app.id = a.application_id WHERE app.name = :applicationId AND a.activation_code = :activationCode AND a.activation_status IN (:states) AND a.timestamp_activation_expire > :currentTimestamp", nativeQuery = true)
    Optional<ActivationRecordEntity> findActivationByCodeWithoutLockMssql(String applicationId, String activationCode, Collection<Byte> states, Date currentTimestamp);

    /**
     * Find the first activation with given activation ID.
     * The activation record is not locked in DB.
     * <p>
     * Native query contains a workaround for MSSQL which avoids deadlock on activations by avoiding locking data.
     * The data needs to be locked later by calling findActivationWithLockMssql().
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    @Query(value = """
            SELECT * FROM pa_activation a WITH (NOLOCK)
            WHERE a.activation_id = :activationId
            """, nativeQuery = true)
    Optional<ActivationRecordEntity> findActivationWithoutLockMssql(String activationId);

    /**
     * Find all activations for given user ID
     * <p>
     * Native query contains a workaround for MSSQL which avoids deadlock on activations by avoiding locking data.
     * The data needs to be locked later by calling findActivationWithLockMssql().
     *
     * @param userId   User ID
     * @param states   Statuses according to which activations should be filtered.
     * @param pageable pageable context
     * @return List of activations for given user
     */
    @Query(value = """
            SELECT * FROM pa_activation a WITH (NOLOCK)
            WHERE a.user_id = :userId
            AND a.activation_status IN (:activationStatuses)
            ORDER BY a.timestamp_created DESC
            OFFSET :#{#pageable.offset} ROWS FETCH NEXT :#{#pageable.pageSize} ROWS ONLY
            """, nativeQuery = true)
    List<ActivationRecordEntity> findByUserIdAndActivationStatusInMssql(String userId, Collection<Byte> states, Pageable pageable);

    /**
     * Find all activations for given user ID and application ID
     * <p>
     * Native query contains a workaround for MSSQL which avoids deadlock on activations by avoiding locking data.
     * The data needs to be locked later by calling findActivationWithLockMssql().
     *
     * @param applicationId      Application ID
     * @param userId             User ID
     * @param activationStatuses Statuses according to which activations should be filtered.
     * @param pageable           pageable context
     * @return List of activations for given user and application
     */
    @Query(value = """
            SELECT * FROM pa_activation a WITH (NOLOCK)
            WHERE a.application_id = :applicationId
            AND a.user_id = :userId
            AND a.activation_status IN (:activationStatuses)
            ORDER BY a.timestamp_created DESC
            OFFSET :#{#pageable.offset} ROWS FETCH NEXT :#{#pageable.pageSize} ROWS ONLY
            """, nativeQuery = true)
    List<ActivationRecordEntity> findByApplicationIdAndUserIdAndActivationStatusInMssql(String applicationId, String userId, Set<ActivationStatus> activationStatuses, Pageable pageable);

    /**
     * Find all activations which match the query criteria.
     * <p>
     * Native query contains a workaround for MSSQL which avoids deadlock on activations by avoiding locking data.
     * The data needs to be locked later by calling findActivationWithLockMssql().
     *
     * @param userIds                 List of user IDs, at least one user ID should be specified.
     * @param applicationIds          List of application IDs, use null value for all applications.
     * @param timestampLastUsedBefore Last used timestamp (timestampLastUsed &lt; timestampLastUsedBefore), use the 1.1.9999 value for any date (null date values in query cause problems in PostgreSQL).
     * @param timestampLastUsedAfter  Last used timestamp (timestampLastUsed &gt;= timestampLastUsedAfter), use the 1.1.1970 value for any date (null date values in query cause problems in PostgreSQL).
     * @param states                  List of activation states to consider.
     * @return List of activations which match the query criteria.
     */
    @Query(value = """
            SELECT * FROM pa_activation a WITH (NOLOCK)
            WHERE a.user_id IN (:userIds)
            AND (:#{#applicationIds == null ? 1 : 0} = 1 OR a.application_id IN (:applicationIds))
            AND a.timestamp_last_used < :timestampLastUsedBefore
            AND a.timestamp_last_used >= :timestampLastUsedAfter
            AND a.activation_status IN (:states)
            """, nativeQuery = true)
    List<ActivationRecordEntity> lookupActivationsMssql(Collection<String> userIds, Collection<String> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, Collection<Byte> states);

    /**
     * Fetch all activations that are in a given state, were expired after a specified timestamp, and are already expired according to a provided current timestamp.
     * <p>
     * Native query contains a workaround for MSSQL which avoids deadlock on activations by avoiding locking data.
     * The data needs to be locked later by calling findActivationWithLockMssql().
     *
     * @param states            Activation states that are used for the lookup.
     * @param startingTimestamp Timestamp after which the activation was expired.
     * @param currentTimestamp  Current timestamp, to identify already expired operations.
     * @return Stream of activations.
     */
    @Query(value = """
            SELECT * FROM pa_activation a WITH (NOLOCK)
            WHERE a.activation_status IN (:states)
            AND a.timestamp_activation_expire >= :startingTimestamp
            AND a.timestamp_activation_expire < :currentTimestamp
            """, nativeQuery = true)
    Stream<ActivationRecordEntity> findAbandonedActivationsMssql(Collection<Byte> states, Date startingTimestamp, Date currentTimestamp);

    /**
     * Find all activations for given user ID
     * <p>
     * Native query contains a workaround for MSSQL which avoids deadlock on activations by avoiding locking data.
     * The data needs to be locked later by calling findActivationWithLockMssql().
     *
     * @param applicationId Application ID.
     * @param externalId    External identifier.
     * @return List of activations for given user
     */
    @Query(value = """
            SELECT * FROM pa_activation a WITH (NOLOCK)
            WHERE a.application_id = :applicationId
            AND a.external_id = :externalId
            """, nativeQuery = true)
    List<ActivationRecordEntity> findByExternalIdMssql(String applicationId, String externalId);
}
