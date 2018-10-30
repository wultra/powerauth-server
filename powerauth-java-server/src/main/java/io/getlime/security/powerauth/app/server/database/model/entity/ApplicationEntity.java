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
import java.util.List;

/**
 * Entity class representing an application.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity(name = "pa_application")
public class ApplicationEntity implements Serializable {

    private static final long serialVersionUID = 1295434927785255417L;

    @Id
    @SequenceGenerator(name = "pa_application", sequenceName = "pa_application_seq")
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_application")
    @Column(name = "id")
    private Long id;

    @Column(name = "name")
    private String name;

    @OneToMany(mappedBy = "application")
    private List<ApplicationVersionEntity> versions;

    /**
     * Default constructor
     */
    public ApplicationEntity() {
    }

    /**
     * Constructor for a new application
     *
     * @param id       Application ID
     * @param name     Application name
     * @param versions Collection of versions
     */
    public ApplicationEntity(Long id, String name, List<ApplicationVersionEntity> versions) {
        super();
        this.id = id;
        this.name = name;
        this.versions = versions;
    }

    /**
     * Get application ID
     *
     * @return Application ID
     */
    public Long getId() {
        return id;
    }

    /**
     * Set application ID
     *
     * @param id Application ID
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get application name
     *
     * @return Application name
     */
    public String getName() {
        return name;
    }

    /**
     * Set application name
     *
     * @param name Application name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get list of versions associated with given application.
     * @return Application versions.
     */
    public List<ApplicationVersionEntity> getVersions() {
        return versions;
    }
}
