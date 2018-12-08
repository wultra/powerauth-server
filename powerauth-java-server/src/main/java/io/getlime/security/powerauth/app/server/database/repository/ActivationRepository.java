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

import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;

import javax.persistence.LockModeType;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Database repository for activation entities.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public interface ActivationRepository extends CrudRepository<ActivationRecordEntity, String> {

    /**
     * Find the first activation with given activation ID.
     * The activation record is locked in DB in PESSIMISTIC_WRITE mode to avoid concurrency issues
     * (DB deadlock, invalid counter value in second transaction, etc.).
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.activationId = ?1")
    ActivationRecordEntity findActivationWithLock(String activationId);

    /**
     * Find activation with given activation ID. This method is MSSQL-specific.
     * The activation is locked using stored procedure sp_getapplock in exclusive mode.
     * The lock is released automatically at the end of the transaction. The stored procedure
     * raises an error in case the lock could not be acquired.
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    @Query(value = "DECLARE @res INT\n" +
            "    EXEC @res = sp_getapplock \n" +
            "                @Resource = ?1,\n" +
            "                @LockMode = 'Exclusive',\n" +
            "                @LockOwner = 'Transaction',\n" +
            "                @LockTimeout = 60000,\n" +
            "                @DbPrincipal = 'public'\n" +
            "    \n" +
            "    IF @res NOT IN (0, 1)\n" +
            "    BEGIN\n" +
            "        RAISERROR ('Unable to acquire lock, error %d, transaction count %d', 16, 1, @res, @@trancount)\n" +
            "    END \n" +
            "    ELSE\n" +
            "    BEGIN\n" +
            "        select * from pa_activation where activation_id = ?1\n" +
            "    END\n", nativeQuery = true)
    ActivationRecordEntity findActivationWithLockMSSQL(String activationId);

    /**
     * Find the first activation with given activation ID.
     * The activation record is not locked in DB.
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.activationId = ?1")
    ActivationRecordEntity findActivationWithoutLock(String activationId);

    /**
     * Get count of activations with given activation ID.
     *
     * @param activationId Activation ID
     * @return Count of activations with given activation ID
     */
    @Query("SELECT COUNT(a) FROM ActivationRecordEntity a WHERE a.activationId = ?1")
    Long getActivationCount(String activationId);

    /**
     * Find all activations for given user ID
     *
     * @param userId User ID
     * @return List of activations for given user
     */
    List<ActivationRecordEntity> findByUserId(String userId);

    /**
     * Find all activations for given user ID and application ID
     *
     * @param applicationId Application ID
     * @param userId        User ID
     * @return List of activations for given user and application
     */
    List<ActivationRecordEntity> findByApplicationIdAndUserId(Long applicationId, String userId);

    /**
     * Find the first activation associated with given application by the activation code.
     * Filter the results by activation state and make sure to apply activation time window.
     *
     * <h5>PowerAuth protocol versions:</h5>
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
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.application.id = ?1 AND a.activationCode = ?2 AND a.activationStatus IN ?3 AND a.timestampActivationExpire > ?4")
    ActivationRecordEntity findCreatedActivationWithoutLock(Long applicationId, String activationCode, Collection<ActivationStatus> states, Date currentTimestamp);

    /**
     * Get count of activations identified by an activation short ID associated with given application.
     *
     * The check for the first half of activation code is required for version 2.0 of PowerAuth crypto. In future the
     * uniqueness check will be extended to whole activation code once version 2.0 of PowerAuth crypto is no longer
     * supported.
     *
     * This method will be removed when crypto version 2.0 is deprecated.
     *
     * @param applicationId     Application ID
     * @param activationIdShort Activation ID short
     * @return Count of activations matching the search criteria
     */
    @Query("SELECT COUNT(a) FROM ActivationRecordEntity a WHERE a.application.id = ?1 AND a.activationCode LIKE ?2%")
    Long getActivationCountByActivationIdShort(Long applicationId, String activationIdShort);

    /**
     * Get count of activations identified by an activation code associated with given application.
     *
     * The check for the first half of activation code is required for version 2.0 of PowerAuth crypto. In future the
     * uniqueness check will be extended to whole activation code once version 2.0 of PowerAuth crypto is no longer
     * supported.
     *
     * @param applicationId  Application ID
     * @param activationCode Activation code
     * @return Count of activations matching the search criteria
     */
    default Long getActivationCountByActivationCode(Long applicationId, String activationCode) {
        if (activationCode == null || activationCode.length() != 23) {
            throw new IllegalArgumentException("Invalid activation code: " + activationCode);
        }
        return getActivationCountByActivationIdShort(applicationId, activationCode.substring(0, 11));
    }

    /**
     * Find the first activation associated with given application by the activation ID short.
     * Filter the results by activation state and make sure to apply activation time window.
     *
     * <h5>PowerAuth protocol versions:</h5>
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
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.application.id = ?1 AND a.activationCode LIKE ?2% AND a.activationStatus IN ?3 AND a.timestampActivationExpire > ?4")
    ActivationRecordEntity findCreatedActivationByShortIdWithoutLock(Long applicationId, String activationIdShort, Collection<ActivationStatus> states, Date currentTimestamp);

}
