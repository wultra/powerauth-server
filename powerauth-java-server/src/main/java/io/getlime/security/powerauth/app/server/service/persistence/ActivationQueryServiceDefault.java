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

import io.getlime.security.powerauth.app.server.configuration.conditions.IsNotMssqlCondition;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Stream;

/**
 * Service for activation queries with pessimistic locking, default implementation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Conditional(IsNotMssqlCondition.class)
public class ActivationQueryServiceDefault implements ActivationQueryService {

    private static final Logger logger = LoggerFactory.getLogger(ActivationQueryServiceDefault.class);

    private final ActivationRepository activationRepository;

    @Autowired
    public ActivationQueryServiceDefault(ActivationRepository activationRepository) {
        this.activationRepository = activationRepository;
    }

    @Override
    public Optional<ActivationRecordEntity> findActivationForUpdate(String activationId) {
        try {
            return activationRepository.findActivationWithLock(activationId);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }

    @Override
    public Optional<ActivationRecordEntity> findActivationWithoutLock(String activationId) {
        try {
            return activationRepository.findActivationWithoutLock(activationId);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }

    @Override
    public List<ActivationRecordEntity> findByUserIdAndActivationStatusIn(String userId, Set<ActivationStatus> activationStatuses, Pageable pageable) {
        try {
            return activationRepository.findByUserIdAndActivationStatusIn(userId, activationStatuses, pageable);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Collections.emptyList();
        }
    }

    @Override
    public List<ActivationRecordEntity> findByApplicationIdAndUserIdAndActivationStatusIn(String applicationId, String userId, Set<ActivationStatus> activationStatuses, Pageable pageable) {
        try {
            return activationRepository.findByApplicationIdAndUserIdAndActivationStatusIn(applicationId, userId, activationStatuses, pageable);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Collections.emptyList();
        }
    }

    @Override
    public Optional<ActivationRecordEntity> findActivationByCodeWithoutLock(String applicationId, String activationCode, Collection<ActivationStatus> states, Date currentTimestamp) {
        try {
            return activationRepository.findActivationByCodeWithoutLock(applicationId, activationCode, states, currentTimestamp);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Optional.empty();
        }
    }

    @Override
    public List<ActivationRecordEntity> lookupActivations(Collection<String> userIds, Collection<String> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, Collection<ActivationStatus> states) {
        try {
            return activationRepository.lookupActivations(userIds, applicationIds, timestampLastUsedBefore, timestampLastUsedAfter, states);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Collections.emptyList();
        }
    }

    @Override
    public Stream<ActivationRecordEntity> findAbandonedActivations(Collection<ActivationStatus> states, Date startingTimestamp, Date currentTimestamp) {
        try {
            return activationRepository.findAbandonedActivations(states, startingTimestamp, currentTimestamp);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Stream.empty();
        }
    }

    @Override
    public List<ActivationRecordEntity> findByExternalId(String applicationId, String externalId) {
        try {
            return activationRepository.findByExternalId(applicationId, externalId);
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return Collections.emptyList();
        }
    }

}