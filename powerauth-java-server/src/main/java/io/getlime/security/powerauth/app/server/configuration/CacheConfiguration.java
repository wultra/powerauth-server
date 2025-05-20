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

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.service.callbacks.CallbackUrlRestClientCacheLoader;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CachedRestClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Cache configuration.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Configuration
@Slf4j
public class CacheConfiguration {

    /**
     * Configuration of the cache for RestClient used for posting callbacks.
     * {@link CallbackUrlEntity#getId()} is used as a cache key.
     *
     * @return Cache for CachedRestClient.
     */
    @Bean
    public LoadingCache<String, CachedRestClient> callbackUrlRestClientCache(
            @Value("${powerauth.service.callbacks.clients.cache.refreshAfterWrite:5m}") final Duration refreshAfterWrite,
            final CallbackUrlRestClientCacheLoader cacheLoader) {

        logger.info("Initializing Callback URL REST Client cache with refreshAfterWrite={}", refreshAfterWrite);
        return Caffeine.newBuilder()
                .refreshAfterWrite(refreshAfterWrite)
                .build(cacheLoader);
    }

}
