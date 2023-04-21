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

import io.getlime.security.powerauth.app.server.converter.CallbackAttributeConverter;
import io.getlime.security.powerauth.app.server.converter.CallbackAuthenticationConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.CallbackUrlTypeConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlType;
import jakarta.persistence.*;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Class representing a callback URL associated with given application.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_application_callback")
public class CallbackUrlEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 3372029113954119581L;

    @Id
    @Column(name = "id", updatable = false, length = 37)
    private String id;

    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    @Column(name = "type", nullable = false)
    @Convert(converter = CallbackUrlTypeConverter.class)
    private CallbackUrlType type;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "callback_url", nullable = false)
    private String callbackUrl;

    @Column(name = "attributes")
    @Convert(converter = CallbackAttributeConverter.class)
    private List<String> attributes;

    @Column(name = "authentication")
    @Convert(converter = CallbackAuthenticationConverter.class)
    private CallbackUrlAuthenticationEntity authentication;

    /**
     * Get the ID of an integration.
     * @return ID of an integration.
     */
    public String getId() {
        return id;
    }

    /**
     * Set the ID of an integration.
     * @param id ID of an integration.
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get the application.
     * @return Application.
     */
    public ApplicationEntity getApplication() {
        return application;
    }

    /**
     * Set application.
     * @param application Application.
     */
    public void setApplication(ApplicationEntity application) {
        this.application = application;
    }

    /**
     * Get the name of an integration.
     * @return Name of an integration.
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of an integration.
     * @param name Name of an integration.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get type of a callback URL.
     * @return Callback URL type.
     */
    public CallbackUrlType getType() {
        return type;
    }

    /**
     * Set type of the callback URL.
     * @param type Callback URL type.
     */
    public void setType(CallbackUrlType type) {
        this.type = type;
    }

    /**
     * Get callback URL string.
     * @return Callback URL string.
     */
    public String getCallbackUrl() {
        return callbackUrl;
    }

    /**
     * Set callback URL string.
     * @param callbackUrl Callback URL string.
     */
    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    /**
     * Get callback attribute settings.
     * @return Callback attribute settings.
     */
    public List<String> getAttributes() {
        return attributes;
    }

    /**
     * Set callback attribute settings.
     * @param attributes Callback attribute settings.
     */
    public void setAttributes(List<String> attributes) {
        this.attributes = attributes;
    }

    /**
     * Get callback request authentication.
     * @return Callback request authentication.
     */
    public CallbackUrlAuthenticationEntity getAuthentication() {
        return authentication;
    }

    /**
     * Set callback request authentication.
     * @param authentication Callback request authentication.
     */
    public void setAuthentication(CallbackUrlAuthenticationEntity authentication) {
        this.authentication = authentication;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CallbackUrlEntity)) return false;
        CallbackUrlEntity that = (CallbackUrlEntity) o;
        return application.equals(that.application) && name.equals(that.getName()) && type == that.type && callbackUrl.equals(that.callbackUrl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(application, name, type, callbackUrl);
    }
}
