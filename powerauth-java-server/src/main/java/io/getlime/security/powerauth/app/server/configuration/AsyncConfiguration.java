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

package io.getlime.security.powerauth.app.server.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Configuration used for the Spring's asynchronous processing
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Configuration
@EnableAsync
@Slf4j
public class AsyncConfiguration {

    @Bean
    public ThreadPoolTaskExecutor callbackUrlEventsThreadPoolExecutor(final PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration) {
        final ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(powerAuthCallbacksConfiguration.getThreadPoolCoreSize());
        executor.setQueueCapacity(powerAuthCallbacksConfiguration.getThreadPoolQueueCapacity());
        executor.setMaxPoolSize(powerAuthCallbacksConfiguration.getThreadPoolMaxSize());
        executor.initialize();
        return executor;
    }

}
