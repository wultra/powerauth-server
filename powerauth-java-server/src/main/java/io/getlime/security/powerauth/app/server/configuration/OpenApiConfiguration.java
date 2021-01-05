/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import org.springdoc.core.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class used for setting up Swagger documentation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "PowerAuth RESTful API Documentation",
                version = "1.0",
                license = @License(
                        name = "AGPL-3.0",
                        url = "https://www.gnu.org/licenses/agpl-3.0.en.html"
                ),
                description = "Documentation for the PowerAuth RESTful API published by the PowerAuth Server.",
                contact = @Contact(
                        name = "Wultra s.r.o.",
                        url = "https://www.wultra.com"
                )
        )
)
public class OpenApiConfiguration {

    @Bean
    public GroupedOpenApi powerAuthApiGroup() {
        String[] packages = {"io.getlime.security.powerauth.app.server.controller.v2", "io.getlime.security.powerauth.app.server.controller.v3"};

        return GroupedOpenApi.builder()
                .group("powerauth")
                .packagesToScan(packages)
                .build();
    }

}