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

import io.getlime.security.powerauth.app.server.database.model.entity.SignatureEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

/**
 * Database repository for accessing signature audit log data.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Repository
public interface SignatureAuditRepository extends CrudRepository<SignatureEntity, Long> {

    /**
     * Return signature audit records for given user and date range.
     *
     * @param userId       User ID.
     * @param startingDate Starting date (date "from").
     * @param endingDate   Ending date (date "to").
     * @return List of {@link SignatureEntity} instances.
     */
    @Query("SELECT s FROM SignatureEntity s WHERE s.activation.userId = :userId AND s.timestampCreated BETWEEN :startingDate AND :endingDate ORDER BY s.timestampCreated DESC, s.id DESC")
    List<SignatureEntity> findSignatureAuditRecordsForUser(String userId, Date startingDate, Date endingDate);

    /**
     * Return signature audit records for given user, application and date range.
     *
     * @param applicationId Application ID.
     * @param userId        User ID.
     * @param startingDate  Starting date (date "from").
     * @param endingDate    Ending date (date "to").
     * @return List of {@link SignatureEntity} instances.
     */
    @Query("SELECT s FROM SignatureEntity s WHERE s.activation.application.id = :applicationId AND s.activation.userId = :userId AND s.timestampCreated BETWEEN :startingDate AND :endingDate ORDER BY s.timestampCreated DESC, s.id DESC")
    List<SignatureEntity> findSignatureAuditRecordsForApplicationAndUser(String applicationId, String userId, Date startingDate, Date endingDate);

}
