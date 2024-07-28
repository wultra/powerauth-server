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
 *
 */

package io.getlime.security.powerauth.app.server.configuration;

import io.getlime.security.powerauth.app.server.configuration.conditions.IsMssqlCondition;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Configuration of READ_COMMITTED_SNAPSHOT transaction isolation level for MSSQL.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Aspect
@Slf4j
@Conditional(IsMssqlCondition.class)
public class MssqlTransactionIsolationConfiguration {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Before("@annotation(org.springframework.transaction.annotation.Transactional)")
    public void setTransactionIsolationLevel() {
        logger.debug("Calling SET TRANSACTION ISOLATION LEVEL SNAPSHOT");
        jdbcTemplate.execute("SET TRANSACTION ISOLATION LEVEL SNAPSHOT");
    }

}