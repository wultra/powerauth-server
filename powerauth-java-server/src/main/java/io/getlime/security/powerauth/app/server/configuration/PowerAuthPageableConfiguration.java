/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration class that handles pagination settings in PowerAuth Server.
 * This includes parameters for default page number and page size.
 * <p>
 * 'defaultPageNumber' is the default page number that is used when no specific
 * page number is provided. It has a minimum value of 0.
 * <p>
 * 'defaultPageSize' is the default number of records per page when no specific
 * page size is provided. It has a minimum value of 1.
 * <p>
 * Both properties are read from the "powerauth.service.pagination" configuration block.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */

@ConfigurationProperties("powerauth.service.pagination")
public record PowerAuthPageableConfiguration(@Min(0) int defaultPageNumber, @Min(1) int defaultPageSize) {
}
