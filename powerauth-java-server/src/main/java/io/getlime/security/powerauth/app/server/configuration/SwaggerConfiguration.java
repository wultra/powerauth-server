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

import com.google.common.base.Predicates;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * Configuration class used for setting up Swagger documentation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@EnableSwagger2
public class SwaggerConfiguration {

    ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("PowerAuth RESTful API Documentation")
                .description("Documentation for the PowerAuth RESTful API published by the PowerAuth Server.")
                .license("AGPL-3.0")
                .licenseUrl("https://www.gnu.org/licenses/agpl-3.0.en.html")
                .version("1.0")
                .build();
    }

    @Bean
    public Docket productApi() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(Predicates.or(
                        RequestHandlerSelectors.basePackage("io.getlime.security.powerauth.app.server.controller.v2"),
                        RequestHandlerSelectors.basePackage("io.getlime.security.powerauth.app.server.controller.v3")
                ))
                .paths(PathSelectors.any())
                .build()
                .apiInfo(apiInfo());
    }

}