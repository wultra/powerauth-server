/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public interface ActivationRepository extends CrudRepository<ActivationRecordEntity, String> {

    /**
     * Find a first activation with given activation ID.
     * The activation record is locked in DB in PESSIMISTIC_WRITE mode to avoid concurrency issues
     * (DB deadlock, invalid counter value in second transaction, etc.).
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.activationId = ?1")
    ActivationRecordEntity findActivation(String activationId);

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
     * Find the first activation associated with given application by the activation ID short.
     * Filter the results by activation state and make sure to apply activation time window.
     * The activation record is locked in DB in PESSIMISTIC_WRITE mode to avoid concurrency issues
     * (DB deadlock, invalid counter value in second transaction, etc.).
     *
     * @param applicationId     Application ID
     * @param activationIdShort Short activation ID
     * @param states            Allowed activation states
     * @param currentTimestamp  Current timestamp
     * @return Activation matching the search criteria or null if not found
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM ActivationRecordEntity a WHERE a.application.id = ?1 AND a.activationIdShort = ?2 AND a.activationStatus IN ?3 AND a.timestampActivationExpire > ?4")
    ActivationRecordEntity findCreatedActivation(Long applicationId, String activationIdShort, Collection<ActivationStatus> states, Date currentTimestamp);

}
