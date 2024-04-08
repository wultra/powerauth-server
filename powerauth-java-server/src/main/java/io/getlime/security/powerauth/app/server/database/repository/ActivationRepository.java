/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Database repository for activation entities.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Repository
public interface ActivationRepository extends JpaRepository<ActivationRecordEntity, String> {

    /**
     * Find the first activation with given activation ID.
     * The activation record is locked in DB in PESSIMISTIC_WRITE mode to avoid concurrency issues
     * (DB deadlock, invalid counter value in second transaction, etc.).
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.activationId = :activationId")
    ActivationRecordEntity findActivationWithLock(String activationId);

    /**
     * Find the first activation with given activation ID.
     * The activation record is not locked in DB.
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.activationId = :activationId")
    ActivationRecordEntity findActivationWithoutLock(String activationId);

    /**
     * Get count of activations with given activation ID.
     *
     * @param activationId Activation ID
     * @return Count of activations with given activation ID
     */
    @Query("SELECT COUNT(a) FROM ActivationRecordEntity a WHERE a.activationId = :activationId")
    Long getActivationCount(String activationId);

    /**
     * Find all activations for given user ID
     *
     * @param userId User ID
     * @param activationStatuses Statuses according to which activations should be filtered.
     * @param pageable pageable context
     * @return List of activations for given user
     */
    List<ActivationRecordEntity> findByUserIdAndActivationStatusIn(String userId, Set<ActivationStatus> activationStatuses, Pageable pageable);

    /**
     * Find all activations for given user ID and application ID
     *
     * @param applicationId Application ID
     * @param userId        User ID
     * @param activationStatuses Statuses according to which activations should be filtered.
     * @param pageable pageable context
     * @return List of activations for given user and application
     */
    List<ActivationRecordEntity> findByApplicationIdAndUserIdAndActivationStatusIn(String applicationId, String userId, Set<ActivationStatus> activationStatuses, Pageable pageable);

    /**
     * Find the first activation associated with given application by the activation code.
     * Filter the results by activation state and make sure to apply activation time window.
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
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.application.id = :applicationId AND a.activationCode = :activationCode AND a.activationStatus IN :states AND a.timestampActivationExpire > :currentTimestamp")
    ActivationRecordEntity findCreatedActivationWithoutLock(String applicationId, String activationCode, Collection<ActivationStatus> states, Date currentTimestamp);

    /**
     * Get count of activations identified by an activation short ID associated with given application.
     * <p>
     * The check for the first half of activation code is required for version 2.0 of PowerAuth crypto. In future the
     * uniqueness check will be extended to whole activation code once version 2.0 of PowerAuth crypto is no longer
     * supported.
     * <p>
     * This method will be removed when crypto version 2.0 is deprecated.
     *
     * @param applicationId     Application ID
     * @param activationIdShort Activation ID short
     * @return Count of activations matching the search criteria
     */
    @Query("SELECT COUNT(a) FROM ActivationRecordEntity a WHERE a.application.id = :applicationId AND a.activationCode LIKE :activationIdShort%")
    Long getActivationCountByActivationIdShort(String applicationId, String activationIdShort);

    /**
     * Get count of activations identified by an activation code associated with given application.
     * <p>
     * The check for the first half of activation code is required for version 2.0 of PowerAuth crypto. In future the
     * uniqueness check will be extended to whole activation code once version 2.0 of PowerAuth crypto is no longer
     * supported.
     *
     * @param applicationId  Application ID
     * @param activationCode Activation code
     * @return Count of activations matching the search criteria
     */
    default Long getActivationCountByActivationCode(String applicationId, String activationCode) {
        if (activationCode == null || activationCode.length() != 23) {
            throw new IllegalArgumentException("Invalid activation code: " + activationCode);
        }
        return getActivationCountByActivationIdShort(applicationId, activationCode.substring(0, 11));
    }

    /**
     * Find the first activation associated with given application by the activation ID short.
     * Filter the results by activation state and make sure to apply activation time window.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param applicationId     Application ID
     * @param activationIdShort Short activation ID
     * @param states            Allowed activation states
     * @param currentTimestamp  Current timestamp
     * @return Activation matching the search criteria or null if not found
     */
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.application.id = :applicationId AND a.activationCode LIKE :activationIdShort% AND a.activationStatus IN :states AND a.timestampActivationExpire > :currentTimestamp")
    ActivationRecordEntity findCreatedActivationByShortIdWithoutLock(String applicationId, String activationIdShort, Collection<ActivationStatus> states, Date currentTimestamp);

    /**
     * Find all activations which match the query criteria.
     * @param userIds List of user IDs, at least one user ID should be specified.
     * @param applicationIds List of application IDs, use null value for all applications.
     * @param timestampLastUsedBefore Last used timestamp (timestampLastUsed &lt; timestampLastUsedBefore), use the 1.1.9999 value for any date (null date values in query cause problems in PostgreSQL).
     * @param timestampLastUsedAfter Last used timestamp (timestampLastUsed &gt;= timestampLastUsedAfter), use the 1.1.1970 value for any date (null date values in query cause problems in PostgreSQL).
     * @param states List of activation states to consider.
     * @return List of activations which match the query criteria.
     */
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.userId IN :userIds AND ((:#{#applicationIds == null} = true) OR a.application.id IN (:applicationIds)) AND a.timestampLastUsed < :timestampLastUsedBefore AND a.timestampLastUsed >= :timestampLastUsedAfter AND a.activationStatus IN :states")
    List<ActivationRecordEntity> lookupActivations(Collection<String> userIds, Collection<String> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, Collection<ActivationStatus> states);

    /**
     * Fetch all activations that are in a given state, were expired after a specified timestamp, and are already expired according to a provided current timestamp.
     * The activations are locked in DB in PESSIMISTIC_WRITE mode to avoid concurrency issues.
     * @param states Activation states that are used for the lookup.
     * @param startingTimestamp Timestamp after which the activation was expired.
     * @param currentTimestamp Current timestamp, to identify already expired operations.
     * @return Stream of activations.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.activationStatus IN :states AND a.timestampActivationExpire >= :startingTimestamp AND a.timestampActivationExpire < :currentTimestamp")
    Stream<ActivationRecordEntity> findAbandonedActivations(Collection<ActivationStatus> states, Date startingTimestamp, Date currentTimestamp);

    /**
     * Find all activations for given user ID
     *
     * @param applicationId Application ID.
     * @param externalId External identifier.
     * @return List of activations for given user
     */
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.application.id = :applicationId AND a.externalId = :externalId")
    List<ActivationRecordEntity> findByExternalId(String applicationId, String externalId);

    /**
     * Return number of unique users who used given application between specified dates. The comparison includes results that
     * have last used timestamps in exact match with provided timestamps (closed interval).
     * @param applicationId Application ID.
     * @param fromDate Starting date.
     * @param toDate Ending date.
     * @return Number of unique users.
     */
    @Query("SELECT COUNT(DISTINCT a.userId) FROM ActivationRecordEntity a WHERE a.application.id = :applicationId AND a.timestampLastUsed >= :fromDate AND a.timestampLastUsed <= :toDate")
    long uniqueUserCountForApplicationBetweenDates(String applicationId, Date fromDate, Date toDate);

}
