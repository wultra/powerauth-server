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

package io.getlime.security.powerauth.app.server.database.repository;

import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hibernate.cfg.AvailableSettings.JAKARTA_LOCK_TIMEOUT;

/**
 * Repository for Callback URL Events.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Repository
public interface CallbackUrlEventRepository extends CrudRepository<CallbackUrlEventEntity, String> {

    /**
     * Lock timeout option to skip locked rows instead of waiting for exclusive lock.
     */
    String SKIP_LOCKED = "-2";

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(value = {@QueryHint(name = JAKARTA_LOCK_TIMEOUT, value = SKIP_LOCKED)})
    @Query("""
            SELECT c FROM CallbackUrlEventEntity c
            WHERE c.id = :id
            AND c.status = io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus.PENDING
            """)
    Optional<CallbackUrlEventEntity> findPendingByIdWithTryLock(String id);

    @Query("""
            SELECT c FROM CallbackUrlEventEntity c
            WHERE c.status = io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus.FAILED
            AND c.timestampNextCall < :timestamp
            """)
    Stream<CallbackUrlEventEntity> findScheduledForRetry(LocalDateTime timestamp, Pageable pageable);

    @Modifying
    @Query("""
            DELETE FROM CallbackUrlEventEntity c
            WHERE c.timestampDeleteAfter < :timestamp
            """)
    void deleteAllAfterRetentionPeriod(LocalDateTime timestamp);

}
