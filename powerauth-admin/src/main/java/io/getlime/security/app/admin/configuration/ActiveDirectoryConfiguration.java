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

package io.getlime.security.app.admin.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Active directory configuration.
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
public class ActiveDirectoryConfiguration {

    @Value("${powerauth.admin.security.activeDirectory.domain}")
    private String activeDirectoryDomain;

    @Value("${powerauth.admin.security.activeDirectory.url}")
    private String activeDirectoryUrl;

    @Value("${powerauth.admin.security.activeDirectory.root}")
    private String activeDirectoryRoot;

    @Value("${powerauth.admin.security.activeDirectory.userSearchFilter}")
    private String activeDirectoryUserSearchFilter;

    public String getActiveDirectoryDomain() {
        return activeDirectoryDomain;
    }

    public void setActiveDirectoryDomain(String activeDirectoryDomain) {
        this.activeDirectoryDomain = activeDirectoryDomain;
    }

    public String getActiveDirectoryUrl() {
        return activeDirectoryUrl;
    }

    public void setActiveDirectoryUrl(String activeDirectoryUrl) {
        this.activeDirectoryUrl = activeDirectoryUrl;
    }

    public String getActiveDirectoryRoot() {
        return activeDirectoryRoot;
    }

    public void setActiveDirectoryRoot(String activeDirectoryRoot) {
        this.activeDirectoryRoot = activeDirectoryRoot;
    }

    public String getActiveDirectoryUserSearchFilter() {
        return activeDirectoryUserSearchFilter;
    }

    public void setActiveDirectoryUserSearchFilter(String activeDirectoryUserSearchFilter) {
        this.activeDirectoryUserSearchFilter = activeDirectoryUserSearchFilter;
    }
}
