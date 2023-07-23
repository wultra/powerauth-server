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
package io.getlime.security.powerauth.app.server.database.model.entity;

import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import jakarta.persistence.*;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Database entity for unique cryptographic values.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Entity
@Table(name = "pa_unique_value")
public class UniqueValueEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -7766414923668550268L;

    @Id
    @Column(name = "unique_value", nullable = false, updatable = false)
    private String uniqueValue;

    @Enumerated
    @Column(name = "type", nullable = false, updatable = false)
    private UniqueValueType type;

    @Column(name = "identifier", updatable = false)
    private String identifier;

    @Column(name = "timestamp_expires", nullable = false, updatable = false)
    private Date timestampExpires;

    public String getUniqueValue() {
        return uniqueValue;
    }

    public void setUniqueValue(String uniqueValue) {
        this.uniqueValue = uniqueValue;
    }

    public UniqueValueType getType() {
        return type;
    }

    public void setType(UniqueValueType type) {
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public Date getTimestampExpires() {
        return timestampExpires;
    }

    public void setTimestampExpires(Date timestampExpires) {
        this.timestampExpires = timestampExpires;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UniqueValueEntity that = (UniqueValueEntity) o;
        return uniqueValue.equals(that.uniqueValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uniqueValue);
    }

    @Override
    public String toString() {
        return "UniqueValueEntity{" +
                "uniqueValue='" + uniqueValue + '\'' +
                ", type=" + type +
                ", identifier='" + identifier + '\'' +
                ", timestampExpires=" + timestampExpires +
                '}';
    }
}
