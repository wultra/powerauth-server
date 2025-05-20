/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.configuration;

import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * Configuration for scheduled jobs.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@Slf4j
public class ScheduledJobConfiguration {

    @Value("${spring.jpa.properties.hibernate.default_schema:}")
    private String defaultSchema;

    private static final String SHEDLOCK_TABLE_NAME = "shedlock";

    @Bean
    public LockProvider lockProvider(DataSource dataSource) {
        final String tableName = StringUtils.isBlank(defaultSchema)
                ? SHEDLOCK_TABLE_NAME
                : defaultSchema + "." + SHEDLOCK_TABLE_NAME;
        logger.info("Following database table will be used by shedlock: {}", tableName);
        return new JdbcTemplateLockProvider(
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(new JdbcTemplate(dataSource))
                        .withTableName(tableName)
                        .usingDbTime()
                        .build());
    }

}
