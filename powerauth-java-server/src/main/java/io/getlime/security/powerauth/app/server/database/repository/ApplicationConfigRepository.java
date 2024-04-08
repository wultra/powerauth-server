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

import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationConfigEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for application configurations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Repository
public interface ApplicationConfigRepository extends CrudRepository<ApplicationConfigEntity, Long> {

    /**
     * Find application configuration by application ID.
     *
     * @param applicationId Application ID.
     * @return List of application config entities.
     */
    List<ApplicationConfigEntity> findByApplicationId(String applicationId);

    /**
     * Find application configuration by application ID and key.
     * @param applicationId Application ID.
     * @param key Configuration key name.
     * @return Optional application config entity.
     */
    Optional<ApplicationConfigEntity> findByApplicationIdAndKey(String applicationId, String key);

}
