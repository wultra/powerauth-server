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
package io.getlime.security.powerauth.app.server.controller;

import javax.validation.constraints.NotNull;

/**
 * Base class for RESTful request object.
 *
 * @param <T> Type of the request object instance.
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class RESTRequestWrapper<T> {

    @NotNull
    private T requestObject;

    /**
     * Default constructor.
     */
    public RESTRequestWrapper() {
    }

    /**
     * Constructor with a correctly typed request object instance.
     *
     * @param requestObject Request object.
     */
    public RESTRequestWrapper(@NotNull T requestObject) {
        this.requestObject = requestObject;
    }

    /**
     * Get request object.
     *
     * @return Request object.
     */
    @NotNull
    public T getRequestObject() {
        return requestObject;
    }

    /**
     * Set request object.
     *
     * @param requestObject Request object.
     */
    public void setRequestObject(T requestObject) {
        this.requestObject = requestObject;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((requestObject == null) ? 0 : requestObject.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        @SuppressWarnings("rawtypes")
        RESTRequestWrapper other = (RESTRequestWrapper) obj;
        if (requestObject == null) {
            if (other.requestObject != null) {
                return false;
            }
        } else if (!requestObject.equals(other.requestObject)) {
            return false;
        }
        return true;
    }

}
