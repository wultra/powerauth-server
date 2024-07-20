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

import io.getlime.security.powerauth.app.server.configuration.conditions.IsMssqlCondition;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.mssql.ActivationRepositoryMssql;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Service for activation queries with pessimistic locking, MSSQL implementation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@Conditional(IsMssqlCondition.class)
public class ActivationQueryServiceMssql implements ActivationQueryService {

    private final ActivationRepositoryMssql activationRepository;

    @Autowired
    public ActivationQueryServiceMssql(ActivationRepositoryMssql activationRepository) {
        this.activationRepository = activationRepository;
    }

    @Override
    public Optional<ActivationRecordEntity> findActivationForUpdate(String activationId) {
        try {
            return activationRepository.findActivationWithLockMssql(activationId);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }

    @Override
    public Optional<ActivationRecordEntity> findActivationByCodeWithoutLock(String applicationId, String activationCode, Collection<ActivationStatus> states, Date currentTimestamp) {
        try {
            final List<Byte> statesBytes = states.stream().map(ActivationStatus::getByte).toList();
            return activationRepository.findActivationByCodeWithoutLockMssql(applicationId, activationCode, statesBytes, currentTimestamp);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }
}