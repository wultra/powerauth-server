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

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Configuration of the Callback URL Event processing.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Configuration
@ConfigurationProperties("powerauth.service.callbacks")
@Getter @Setter
public class PowerAuthCallbacksConfiguration {

    /**
     * Default maximum number of attempts in case the corresponding Callback URL does not define any.
     */
    private int defaultMaxAttempts = 1;

    /**
     * Default retention period of the event in case the corresponding Callback URL does not define any.
     */
    private Duration defaultRetentionPeriod = Duration.ofDays(30);

    /**
     * Default initial backoff between attempts in case the corresponding Callback URL does not define any.
     */
    private long defaultInitialBackoffMilliseconds = 2_000;

    /**
     * Maximum number of failed Callback URL Events that will be dispatched again in a single scheduled job run.
     */
    private int failedCallbackUrlEventsRetryLimit = 100;

    /**
     * Maximum possible backoff period between successive attempts.
     */
    private long maxBackoffMilliseconds = 32_000;

    /**
     * Multiplier used to calculate the backoff period.
     */
    private double backoffMultiplier = 1.5;

    /**
     * Number of core threads in the thread pool used by Callback URL Event listener.
     */
    private int threadPoolCoreSize = 1;

}
