/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.database.repository;

import com.wultra.security.powerauth.app.server.database.model.entity.ConfigStoreEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ConfigScope;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for configuration store records.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Repository
public interface ConfigStoreRepository extends CrudRepository<ConfigStoreEntity, Long> {

    /**
     * Find the configuration store records visible for a given activation (both application and activation scopes).
     *
     * @param applicationId Application ID.
     * @param activationId Activation ID.
     * @return List of activation-scope config store records.
     */
    @Query("SELECT c FROM ConfigStoreEntity c WHERE (c.application.id = :applicationId AND c.activation IS NULL) OR c.activation.activationId = :activationId")
    List<ConfigStoreEntity> findVisibleForActivation(@Param("applicationId") String applicationId, @Param("activationId") String activationId);

    /**
     * Find the per-activation configuration store record for the given activation.
     *
     * @param activationId Activation ID.
     * @return Optional per-activation config store record.
     */
    @Query("SELECT c FROM ConfigStoreEntity c WHERE c.activation.activationId = :activationId")
    Optional<ConfigStoreEntity> findByActivationId(@Param("activationId") String activationId);

    /**
     * Find the application-level configuration store record for the given application and scope.
     *
     * @param applicationId Application ID.
     * @param scope Configuration scope.
     * @return Optional application-level config store record.
     */
    @Query("SELECT c FROM ConfigStoreEntity c WHERE c.application.id = :applicationId AND c.activation IS NULL AND c.scope = :scope")
    Optional<ConfigStoreEntity> findByApplicationAndScope(@Param("applicationId") String applicationId, @Param("scope") ConfigScope scope);

    /**
     * Find all application-level configuration store records for the given application.
     *
     * @param applicationId Application ID.
     * @return List of application-level config store records.
     */
    @Query("SELECT c FROM ConfigStoreEntity c WHERE c.application.id = :applicationId AND c.activation IS NULL")
    List<ConfigStoreEntity> findAllForApplication(@Param("applicationId") String applicationId);

    /**
     * Delete the per-activation configuration store record bound to the given activation.
     *
     * @param activationId Activation ID.
     */
    @Modifying
    @Query("DELETE FROM ConfigStoreEntity c WHERE c.activation.activationId = :activationId")
    void deleteByActivationId(@Param("activationId") String activationId);

}
