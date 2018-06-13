/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * PowerAuth 2.0 Server main application class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@SpringBootApplication
public class Application {

    static {
        // TODO temporary workaround for Spring boot duplicate logging issue on Tomcat:
        // https://github.com/spring-projects/spring-boot/issues/13470
        Logger rootLogger = LogManager.getLogManager().getLogger("");
        Handler[] handlers = rootLogger.getHandlers();
        for (Handler handler : handlers) {
            // By default Tomcat adds ConsoleHandler to root logger which needs to be removed to avoid duplicate logging.
            // Removal of handlers during SLF4J initialization does not happen automatically after migration to Spring boot 2.0.0.
            // Once the issue is fixed in Spring boot project, we should remove this workaround.
            if (handler instanceof ConsoleHandler) {
                rootLogger.removeHandler(handler);
            }
        }

        // Initialize Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
        // Set key convertor
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());

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
