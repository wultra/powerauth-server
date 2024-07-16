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

import java.util.Collection;
import java.util.Date;
import java.util.Optional;

/**
 * Service for activation queries with pessimistic locking.
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
     * Find an activation by code without a lock. The record may be updated by another transaction.
     * @param applicationId Application ID.
     * @param activationCode Activation code.
     * @param states Allowed states.
     * @param currentTimestamp Current timestamp.
     * @return Activation, if present.
     */
    Optional<ActivationRecordEntity> findActivationByCodeWithoutLock(String applicationId, String activationCode, Collection<ActivationStatus> states, Date currentTimestamp);

}