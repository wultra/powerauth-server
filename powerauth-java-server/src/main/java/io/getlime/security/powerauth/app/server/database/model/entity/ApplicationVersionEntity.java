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

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
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
@Getter @Setter
public class ApplicationVersionEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -5107229264389219556L;

    /**
     * Version RID.
     */
    @Id
    @SequenceGenerator(name = "pa_application_version", sequenceName = "pa_application_version_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_application_version")
    @Column(name = "id")
    private Long rid;

    /**
     * Associated application
     */
    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    /**
     * Version ID.
     */
    @Column(name = "name")
    private String id;

    /**
     * Application key.
     */
    @Column(name = "application_key")
    private String applicationKey;

    /**
     * Application secret.
     */
    @Column(name = "application_secret")
    private String applicationSecret;

    /**
     * Flag indicating if this version is still supported (can be used for signatures).
     */
    @Column(name = "supported")
    private Boolean supported;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApplicationVersionEntity that = (ApplicationVersionEntity) o;
        return Objects.equals(application, that.application) &&
                Objects.equals(id, that.id) &&
                Objects.equals(applicationKey, that.applicationKey) &&
                Objects.equals(applicationSecret, that.applicationSecret) &&
                Objects.equals(supported, that.supported);
    }

    @Override
    public int hashCode() {
        return Objects.hash(application, id, applicationKey, applicationSecret, supported);
    }
}
