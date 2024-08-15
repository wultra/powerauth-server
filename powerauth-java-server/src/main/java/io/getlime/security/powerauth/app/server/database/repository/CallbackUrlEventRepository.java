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
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository for Callback URL Events.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Repository
public interface CallbackUrlEventRepository extends CrudRepository<CallbackUrlEventEntity, Long> {

    @Query("""
            SELECT c FROM CallbackUrlEventEntity c
            WHERE c.status = io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus.PENDING
            AND c.timestampNextCall < :timestamp
            ORDER BY c.timestampNextCall DESC
            """)
    List<CallbackUrlEventEntity> findPending(LocalDateTime timestamp, Pageable pageable);

    @Modifying
    @Query("""
            DELETE FROM CallbackUrlEventEntity c
            WHERE c.status = io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus.COMPLETED
            AND c.timestampDeleteAfter < :timestamp
            """)
    void deleteCompletedAfterRetentionPeriod(LocalDateTime timestamp);

    @Modifying
    @Query("""
            UPDATE CallbackUrlEventEntity c
            SET c.status = io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus.PENDING,
                c.timestampNextCall = c.timestampLastCall
            WHERE c.id = :id
            """)
    void updateEventToPendingState(Long id);

    @Modifying
    @Query("""
            UPDATE CallbackUrlEventEntity c
            SET c.status = io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus.PENDING,
                c.timestampNextCall = c.timestampLastCall
            WHERE c.status = io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus.PROCESSING
            AND c.timestampLastCall < :timestamp
            """)
    int updateStaleEventsToPendingState(LocalDateTime timestamp);

}
