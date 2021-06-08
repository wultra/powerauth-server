/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.Date;

/**
 * Entity representing the Shedlock items. The entity is not used directly via JPA repositories.
 * We have it here so that databases that create schema based on entities have easier task in
 * picking the entire schema. This is particularly helpful while running tests with in-memory
 * databases.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "shedlock")
public class ShedlockEntity implements Serializable {

    private static final long serialVersionUID = 3791580797958213663L;

    @Id
    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "lock_until", nullable = false)
    private Date lockUntil;

    @Column(name = "locked_at", nullable = false)
    private Date lockedAt;

    @Column(name = "locked_by", nullable = false)
    private String lockedBy;

    /**
     * Get name.
     * @return Name.
     */
    public String getName() {
        return name;
    }

    /**
     * Set name.
     * @param name Name.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get lock until.
     * @return Lock until.
     */
    public Date getLockUntil() {
        return lockUntil;
    }

    /**
     * Set lock until.
     * @param lockUntil Lock until.
     */
    public void setLockUntil(Date lockUntil) {
        this.lockUntil = lockUntil;
    }

    /**
     * Get locked at.
     * @return Locked at.
     */
    public Date getLockedAt() {
        return lockedAt;
    }

    /**
     * Set locked at.
     * @param lockedAt Locked at.
     */
    public void setLockedAt(Date lockedAt) {
        this.lockedAt = lockedAt;
    }

    /**
     * Get locked by.
     * @return Locked by.
     */
    public String getLockedBy() {
        return lockedBy;
    }

    /**
     * Set locked by.
     * @param lockedBy Locked by.
     */
    public void setLockedBy(String lockedBy) {
        this.lockedBy = lockedBy;
    }
}
