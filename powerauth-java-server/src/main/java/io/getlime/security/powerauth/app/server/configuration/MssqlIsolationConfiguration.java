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

import com.zaxxer.hikari.HikariDataSource;
import io.getlime.security.powerauth.app.server.configuration.conditions.IsMssqlCondition;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.lang.NonNull;

/**
 * Configuration of SNAPSHOT isolation for MSSQL.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
@Slf4j
@EnableAspectJAutoProxy
@Conditional(IsMssqlCondition.class)
public class MssqlIsolationConfiguration {

    @Bean
    public static BeanPostProcessor dataSourcePostProcessor() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessBeforeInitialization(@NonNull Object bean, @NonNull String beanName) throws BeansException {
                return bean;
            }

            @Override
            public Object postProcessAfterInitialization(@NonNull Object bean, @NonNull String beanName) throws BeansException {
                if (bean instanceof HikariDataSource hikariDataSource) {
                    logger.info("Setting initialization SQL: SET TRANSACTION ISOLATION LEVEL SNAPSHOT");
                    hikariDataSource.setConnectionInitSql("SET TRANSACTION ISOLATION LEVEL SNAPSHOT");
                }
                return bean;
            }
        };
    }

}
