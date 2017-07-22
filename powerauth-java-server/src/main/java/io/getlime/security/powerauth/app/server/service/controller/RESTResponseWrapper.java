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
package io.getlime.security.powerauth.app.server.service.controller;

import javax.validation.constraints.NotNull;

/**
 * Base class for RESTful response object.
 *
 * @param <T> Type of the response object instance.
 * @author Petr Dvorak
 */
public class RESTResponseWrapper<T> {

    @NotNull
    private T responseObject;

    @NotNull
    private String status;

    /**
     * Default constructor.
     */
    public RESTResponseWrapper() {
    }

    /**
     * Constructor with status and response object.
     *
     * @param status         Status - "OK" or "ERROR".
     * @param responseObject Response object instance.
     */
    public RESTResponseWrapper(@NotNull String status, @NotNull T responseObject) {
        this.status = status;
        this.responseObject = responseObject;
    }

    /**
     * Get response object.
     *
     * @return Response object.
     */
    public T getResponseObject() {
        return responseObject;
    }

    /**
     * Set response object.
     *
     * @param responseObject Response object.
     */
    public void setResponseObject(T responseObject) {
        this.responseObject = responseObject;
    }

    /**
     * Get response status.
     *
     * @return Status.
     */
    public String getStatus() {
        return status;
    }

    /**
     * Set response status.
     *
     * @param status Status.
     */
    public void setStatus(String status) {
        this.status = status;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((responseObject == null) ? 0 : responseObject.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
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
        RESTResponseWrapper other = (RESTResponseWrapper) obj;
        if (responseObject == null) {
            if (other.responseObject != null) {
                return false;
            }
        } else if (!responseObject.equals(other.responseObject)) {
            return false;
        }
        if (status == null) {
            if (other.status != null) {
                return false;
            }
        } else if (!status.equals(other.status)) {
            return false;
        }
        return true;
    }

}
