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

import io.getlime.security.powerauth.app.server.database.model.converter.ApplicationRoleConverter;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Entity class representing an application.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_application")
@Getter @Setter
public class ApplicationEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1295434927785255417L;

    /**
     * Application RID.
     */
    @Id
    @SequenceGenerator(name = "pa_application", sequenceName = "pa_application_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_application")
    @Column(name = "id")
    private Long rid;

    /**
     * Application ID.
     */
    @Column(name = "name", unique = true)
    private String id;

    /**
     * Application roles.
     */
    @Column(name = "roles")
    @Convert(converter = ApplicationRoleConverter.class)
    private final List<String> roles = new ArrayList<>();

    /**
     * List of versions associated with given application.
     */
    @OneToMany(mappedBy = "application")
    private final List<ApplicationVersionEntity> versions = new ArrayList<>();

    /**
     * The list of callbacks for given application.
     */
    @OneToMany(mappedBy = "application")
    private final List<CallbackUrlEntity> callbacks = new ArrayList<>();

    /**
     * The list of recovery codes.
     */
    @OneToMany(mappedBy = "application")
    private final List<RecoveryCodeEntity> recoveryCodes = new ArrayList<>();

    /**
     * No-arg constructor.
     */
    public ApplicationEntity() {
    }

    /**
     * Constructor for a new application.
     *
     * @param rid       Application RID.
     * @param id     Application ID.
     * @param roles    Application roles.
     * @param versions Collection of versions.
     */
    public ApplicationEntity(Long rid, String id, List<String> roles, List<ApplicationVersionEntity> versions) {
        this.rid = rid;
        this.id = id;
        this.roles.addAll(roles);
        this.versions.addAll(versions);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApplicationEntity that = (ApplicationEntity) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(roles, that.roles) &&
                Objects.equals(versions, that.versions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, roles, versions);
    }

    @Override
    public String toString() {
        return "ApplicationEntity{" +
                "rid=" + rid +
                ", id='" + id + '\'' +
                ", roles=" + roles +
                ", versions=" + versions +
                ", callbacks=" + callbacks +
                ", recoveryCodes=" + recoveryCodes +
                '}';
    }
}
