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
package io.getlime.security.powerauth.app.server;

import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.Security;

/**
 * PowerAuth Server main application class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@SpringBootApplication
@EnableScheduling
@EnableCaching
@EnableSchedulerLock(defaultLockAtMostFor = "60m")
@ConfigurationPropertiesScan
@EnableJpaRepositories(basePackages = {"io.getlime.security.powerauth.app.server", "com.wultra.powerauth.fido2"})
@EntityScan(basePackages = {"io.getlime.security.powerauth.app.server", "com.wultra.powerauth.fido2"})
public class Application {

    static {
        // Initialize Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Main application method.
     *
     * @param args Arguments.
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}
