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

package io.getlime.security.powerauth.app.server.service.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;

/**
 * Class holding the configuration data of this PowerAuth 2.0 Server
 * instance. Default values are in "application.properties" file.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Configuration
public class PowerAuthServiceConfiguration {

    @Value("${powerauth.service.applicationName}")
    private String applicationName;

    @Value("${powerauth.service.applicationDisplayName}")
    private String applicationDisplayName;

    @Value("${powerauth.service.applicationEnvironment}")
    private String applicationEnvironment;

    @Value("${powerauth.service.restrictAccess}")
    private Boolean restrictAccess;

    /**
     * Get application name, usually used as a "unique code" for the application within
     * a server infrastructure.
     *
     * @return Application name.
     */
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * Set application name.
     *
     * @param applicationName Application name.
     */
    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    /**
     * Get application display name, usually used as a "visual representation" of the
     * application within a server infrastructure.
     *
     * @return Application display name.
     */
    public String getApplicationDisplayName() {
        return applicationDisplayName;
    }

    /**
     * Set application display name.
     *
     * @param applicationDisplayName Application display name.
     */
    public void setApplicationDisplayName(String applicationDisplayName) {
        this.applicationDisplayName = applicationDisplayName;
    }

    /**
     * Get the application environment name.
     *
     * @return Application environment name.
     */
    public String getApplicationEnvironment() {
        return applicationEnvironment;
    }

    /**
     * Set the application environment name.
     *
     * @param applicationEnvironment Application environment name.
     */
    public void setApplicationEnvironment(String applicationEnvironment) {
        this.applicationEnvironment = applicationEnvironment;
    }

    /**
     * Get the value of a flag that indicates that access to the PA2.0 Server should be restricted
     * to predefined integrations.
     *
     * @return Flag with access restriction information.
     */
    public Boolean getRestrictAccess() {
        return restrictAccess;
    }

    /**
     * Set the value of a flag that indicates that access to the PA2.0 Server should be restricted
     * to predefined integrations.
     *
     * @param restrictAccess Flag with access restriction information.
     */
    public void setRestrictAccess(Boolean restrictAccess) {
        this.restrictAccess = restrictAccess;
    }

    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("/i18n/errors_");
        source.setUseCodeAsDefaultMessage(true);
        return source;
    }

}
