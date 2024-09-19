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

import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlType;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Database repository for the callback URL entities.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Repository
public interface CallbackUrlRepository extends CrudRepository<CallbackUrlEntity, String> {

    List<CallbackUrlEntity> findByApplicationIdOrderByName(String applicationId);

    List<CallbackUrlEntity> findByApplicationIdAndTypeOrderByName(String applicationId, CallbackUrlType type);

    @Modifying
    @Query("""
           UPDATE CallbackUrlEntity c
           SET c.failureCount = c.failureCount + 1, c.timestampLastFailure = :timestampLastFailure
           WHERE c.id = :id
           """)
    void incrementFailureCount(String id, LocalDateTime timestampLastFailure);

    @Modifying
    @Query("""
           UPDATE CallbackUrlEntity c
           SET c.failureCount = 0, c.timestampLastFailure = NULL
           WHERE c.id = :id
           """)
    void resetFailureCount(String id);

}
