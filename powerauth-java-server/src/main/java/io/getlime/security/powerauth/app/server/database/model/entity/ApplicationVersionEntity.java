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
package io.getlime.security.powerauth.app.server.database.model.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Objects;

/**
 * Entity class representing an application version. Each activation is associated with a single application,
 * that may have multiple versions.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_application_version")
public class ApplicationVersionEntity implements Serializable {

    private static final long serialVersionUID = -5107229264389219556L;

    @Id
    @SequenceGenerator(name = "pa_application_version", sequenceName = "pa_application_version_seq")
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_application_version")
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    @Column(name = "name")
    private String name;

    @Column(name = "application_key")
    private String applicationKey;

    @Column(name = "application_secret")
    private String applicationSecret;

    @Column(name = "supported")
    private Boolean supported;

    /**
     * Get associated application
     *
     * @return Associated application
     */
    public ApplicationEntity getApplication() {
        return application;
    }

    /**
     * Set associated application
     *
     * @param application Associated application
     */
    public void setApplication(ApplicationEntity application) {
        this.application = application;
    }

    /**
     * Get application key
     *
     * @return Application key
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key
     *
     * @param applicationKey Application key
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get application secret
     *
     * @return Application secret
     */
    public String getApplicationSecret() {
        return applicationSecret;
    }

    /**
     * Set application secret
     *
     * @param applicationSecret Application secret
     */
    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    /**
     * Get version ID
     *
     * @return version ID
     */
    public Long getId() {
        return id;
    }

    /**
     * Set version ID
     *
     * @param id Version ID
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get version name
     *
     * @return Version name
     */
    public String getName() {
        return name;
    }

    /**
     * Set version name
     *
     * @param name Version name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get flag indicating if this version is still supported.
     *
     * @return Flag indicating if this version is still supported (can be used for signatures)
     */
    public Boolean getSupported() {
        return supported;
    }

    /**
     * Set flag indicating if this version is still supported.
     *
     * @param supported Flag indicating if this version is still supported (can be used for signatures)
     */
    public void setSupported(Boolean supported) {
        this.supported = supported;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApplicationVersionEntity that = (ApplicationVersionEntity) o;
        return Objects.equals(application, that.application) &&
                Objects.equals(name, that.name) &&
                Objects.equals(applicationKey, that.applicationKey) &&
                Objects.equals(applicationSecret, that.applicationSecret) &&
                Objects.equals(supported, that.supported);
    }

    @Override
    public int hashCode() {
        return Objects.hash(application, name, applicationKey, applicationSecret, supported);
    }
}
