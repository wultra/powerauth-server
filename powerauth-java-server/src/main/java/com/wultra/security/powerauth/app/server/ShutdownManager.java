/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server;

import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import jakarta.annotation.PreDestroy;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.security.Security;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Shutdown manager for BC library and threads which do not get shutdown gracefully in time of application exit.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@AllArgsConstructor
@Slf4j
public class ShutdownManager {

    private static final long TIMEOUT_SHUTDOWN_SECONDS = 10;

    private final SdkTracerProvider sdkTracerProvider;
    private final SdkLoggerProvider sdkLoggerProvider;
    private final MeterRegistry meterRegistry;

    private static final String[] THREAD_NAME_PREFIXES = {
            "BatchSpanProcessor_WorkerThread",
            "BatchLogRecordProcessor_WorkerThread",
            "prometheus-metrics-scheduler"
    };

    @PreDestroy
    public void shutdown() {
        if (Security.getProvider("BC") != null) {
            Security.removeProvider("BC");
            logger.info("BouncyCastle provider removed during shutdown.");
        }
        if (sdkTracerProvider != null) {
            sdkTracerProvider.shutdown().join(TIMEOUT_SHUTDOWN_SECONDS, TimeUnit.SECONDS);
        }
        if (sdkLoggerProvider != null) {
            sdkLoggerProvider.shutdown().join(TIMEOUT_SHUTDOWN_SECONDS, TimeUnit.SECONDS);
        }
        if (meterRegistry != null) {
            try {
                final Class<?> schedulerClass = Class.forName("io.prometheus.metrics.core.util.Scheduler");
                final Field executorField = schedulerClass.getDeclaredField("executor");
                executorField.setAccessible(true);
                final ScheduledExecutorService executor = (ScheduledExecutorService) executorField.get(null);
                if (executor != null && !executor.isShutdown()) {
                    executor.shutdownNow();
                }
            } catch (NoSuchFieldException | IllegalAccessException | ClassNotFoundException e) {
                logger.error("Could not stop Prometheus metrics scheduler", e);
            }
        }
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            for (String prefix : THREAD_NAME_PREFIXES) {
                if (thread.getName().startsWith(prefix) && thread.isAlive()) {
                    thread.interrupt();
                }
            }
        }
    }
}