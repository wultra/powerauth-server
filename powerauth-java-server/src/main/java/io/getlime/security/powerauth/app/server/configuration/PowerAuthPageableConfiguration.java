/*
 * PowerAuth Server and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * PowerAuthPageableConfiguration is a configuration class for handling pagination settings.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 *
 */
@Configuration
@ConfigurationProperties("powerauth.service.pagination")
@Data
public class PowerAuthPageableConfiguration {

    /**
     * Default page number for pagination.
     */
    private int defaultPageNumber;

    /**
     * Default page size for pagination.
     */
    private int defaultPageSize;
}

