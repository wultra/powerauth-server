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

package com.wultra.powerauth.fido2.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Configuration of the FIDO2 Authenticators cache periodical eviction.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Configuration
@Slf4j
public class CachingConfig {

    @CacheEvict(value = "fido2-authenticators-cache", allEntries = true)
    @Scheduled(fixedDelayString = "${powerauth.service.scheduled.job.fido2AuthenticatorCacheEviction:3600000}")
    public void evictFido2AuthenticatorCache() {
        logger.debug("Flush FIDO2 Authenticators cache.");
    }

}
