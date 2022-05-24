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

import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Database repository class for access to applications
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Repository
public interface ApplicationRepository extends CrudRepository<ApplicationEntity, Long> {

    /**
     * Find application by ID.
     *
     * @param applicationId Application ID.
     * @return Optional application entity with given name, returns application matching the name
     */
    Optional<ApplicationEntity> findById(String applicationId);

    /**
     * Find distinct applications are match the ID values.
     * @param applicationIds List of application names.
     * @return Count of distinct applications with provided IDs.
     */
    List<ApplicationEntity> findAllByIdIn(List<String> applicationIds);
}
