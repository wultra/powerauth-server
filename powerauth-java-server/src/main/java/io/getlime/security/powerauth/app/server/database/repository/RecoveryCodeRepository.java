/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.database.model.entity.RecoveryCodeEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Database repository for recovery code entities.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Repository
public interface RecoveryCodeRepository extends CrudRepository<RecoveryCodeEntity, Long> {

    /**
     * Get count of recovery codes with given application ID and recovery code.
     * @param applicationId Application ID.
     * @param recoveryCode Recovery code.
     * @return Count of recovery codes with given application ID and recovery code.
     */
    @Query("SELECT COUNT(r) FROM RecoveryCodeEntity r WHERE r.applicationId = :applicationId AND r.recoveryCode = :recoveryCode")
    Long getRecoveryCodeCount(Long applicationId, String recoveryCode);

    /**
     * Find all recovery codes for given user ID.
     * @param userId User ID.
     * @return User recovery codes.
     */
    @Query("SELECT r FROM RecoveryCodeEntity r WHERE r.userId = :userId ORDER BY r.timestampCreated DESC")
    List<RecoveryCodeEntity> findAllByUserId(String userId);

    /**
     * Find all recovery codes for given activation ID.
     * @param activationId Activation ID.
     * @return Recovery codes matching search criteria.
     */
    @Query("SELECT r FROM RecoveryCodeEntity r WHERE r.activationId = :activationId ORDER BY r.timestampCreated DESC")
    List<RecoveryCodeEntity> findAllByActivationId(String activationId);

    /**
     * Find all recovery codes for given application ID and user ID.
     * @param applicationId Application ID.
     * @param userId User ID.
     * @return Recovery codes matching search criteria.
     */
    @Query("SELECT r FROM RecoveryCodeEntity r WHERE r.applicationId = :applicationId AND r.userId = :userId ORDER BY r.timestampCreated DESC")
    List<RecoveryCodeEntity> findAllByApplicationIdAndUserId(Long applicationId, String userId);

    /**
     * Find all recovery codes for given application ID and user ID.
     * @param applicationId Application ID.
     * @param activationId Activation ID.
     * @return Recovery codes matching search criteria.
     */
    @Query("SELECT r FROM RecoveryCodeEntity r WHERE r.applicationId = :applicationId AND r.activationId = :activationId ORDER BY r.timestampCreated DESC")
    List<RecoveryCodeEntity> findAllByApplicationIdAndActivationId(Long applicationId, String activationId);

    /**
     * Find all recovery codes for given application ID, user ID and activation ID.
     * @param applicationId Application ID.
     * @param userId User ID.
     * @param activationId Activation ID.
     * @return Recovery codes matching search criteria.
     */
    @Query("SELECT r FROM RecoveryCodeEntity r WHERE r.applicationId = :applicationId AND r.userId = :userId AND r.activationId = :activationId ORDER BY r.timestampCreated DESC")
    List<RecoveryCodeEntity> findAllRecoveryCodes(Long applicationId, String userId, String activationId);

    /**
     * Find recovery code entity for given application ID and recovery code.
     * @param applicationId Application ID.
     * @param recoveryCode Recovery code.
     * @return Recovery code entity matching search criteria.
     */
    RecoveryCodeEntity findByApplicationIdAndRecoveryCode(Long applicationId, String recoveryCode);

}
