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

import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * Database repository for accessing Master Key Pair data.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Repository
public interface MasterKeyPairRepository extends CrudRepository<MasterKeyPairEntity, Long> {

    /**
     * Find one newest master key pair with a given application ID
     *
     * @param id Application ID
     * @return The newest Master Key Pair for given application.
     */
    MasterKeyPairEntity findFirstByApplicationIdOrderByTimestampCreatedDesc(Long id);

}
