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
package io.getlime.security.powerauth.app.server.service.persistence;

import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import org.springframework.data.domain.Pageable;

import java.util.*;
import java.util.stream.Stream;

/**
 * Service for activation queries.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface ActivationQueryService {

    /**
     * Find an activation and lock it for an update.
     * @param activationId Activation ID.
     * @return Locked activation, if present.
     */
    Optional<ActivationRecordEntity> findActivationForUpdate(String activationId);

    /**
     * Find the first activation with given activation ID.
     * The activation record is not locked in DB.
     *
     * @param activationId Activation ID
     * @return Activation with given ID or null if not found
     */
    Optional<ActivationRecordEntity> findActivationWithoutLock(String activationId);

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
     * Find an activation by code without a lock. The record may be updated by another transaction.
     * @param applicationId Application ID.
     * @param activationCode Activation code.
     * @param states Allowed states.
     * @param currentTimestamp Current timestamp.
     * @return Activation, if present.
     */
    Optional<ActivationRecordEntity> findActivationByCodeWithoutLock(String applicationId, String activationCode, Collection<ActivationStatus> states, Date currentTimestamp);

    /**
     * Find all activations which match the query criteria.
     * @param userIds List of user IDs, at least one user ID should be specified.
     * @param applicationIds List of application IDs, use null value for all applications.
     * @param timestampLastUsedBefore Last used timestamp (timestampLastUsed &lt; timestampLastUsedBefore), use the 1.1.9999 value for any date (null date values in query cause problems in PostgreSQL).
     * @param timestampLastUsedAfter Last used timestamp (timestampLastUsed &gt;= timestampLastUsedAfter), use the 1.1.1970 value for any date (null date values in query cause problems in PostgreSQL).
     * @param states List of activation states to consider.
     * @return List of activations which match the query criteria.
     */
    List<ActivationRecordEntity> lookupActivations(Collection<String> userIds, Collection<String> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, Collection<ActivationStatus> states);

    /**
     * Fetch all activations that are in a given state, were expired after a specified timestamp, and are already expired according to a provided current timestamp.
     * @param states Activation states that are used for the lookup.
     * @param startingTimestamp Timestamp after which the activation was expired.
     * @param currentTimestamp Current timestamp, to identify already expired operations.
     * @return Stream of activations.
     */
    Stream<ActivationRecordEntity> findAbandonedActivations(Collection<ActivationStatus> states, Date startingTimestamp, Date currentTimestamp);

    /**
     * Find all activations for given user ID
     *
     * @param applicationId Application ID.
     * @param externalId External identifier.
     * @return List of activations for given user
     */
    List<ActivationRecordEntity> findByExternalId(String applicationId, String externalId);


}