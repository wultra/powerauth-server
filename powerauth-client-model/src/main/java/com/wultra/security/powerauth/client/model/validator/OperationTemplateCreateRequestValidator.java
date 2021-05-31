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

package com.wultra.security.powerauth.client.model.validator;

import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;

import java.util.HashSet;
import java.util.Set;

/**
 * Validator for OperationTemplateCreateRequest class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class OperationTemplateCreateRequestValidator {

    public static String validate(OperationTemplateCreateRequest source) {
        if (source == null) {
            return "Operation template create request must not be null";
        }
        if (source.getTemplateName() == null) {
            return "Template name must not be null when creating operation template";
        }
        if (source.getTemplateName().isEmpty()) {
            return "Template name must not be empty when creating operation template";
        }
        if (source.getOperationType() == null) {
            return "Template operation type must not be null when creating operation template";
        }
        if (source.getOperationType().isEmpty()) {
            return "Template operation type must not be empty when creating operation template";
        }
        if (source.getSignatureType() == null) {
            return "Template signature types must not be null when creating operation template";
        }
        if (source.getSignatureType().isEmpty()) {
            return "Template signature types must contain at least one value";
        }
        if (hasDuplicate(source.getSignatureType())) {
            return "Template signature types must be unique.";
        }
        if (source.getDataTemplate() == null) {
            return "Template data must not be null when creating operation template";
        }
        if (source.getDataTemplate().isEmpty()) {
            return "Template data must not be empty when creating operation template";
        }
        if (source.getExpiration() == null) {
            return "Template expiration value must not be null when creating operation template";
        }
        if (source.getExpiration() <= 0) {
            return "Template expiration value must not be greater than zero";
        }
        if (source.getMaxFailureCount() == null) {
            return "Template maximum allowed failure count must not be null";
        }
        if (source.getMaxFailureCount() <= 0) {
            return "Template maximum allowed failure count must be greater than zero";
        }
        return null;
    }

    /**
     * Check duplicates in iterable.
     * @param all Iterable to check.
     * @param <T> Generic type.
     * @return True if iterable contains a duplicate value, false otherwise.
     */
    private static <T> boolean hasDuplicate(Iterable<T> all) {
        if (all != null) {
            final Set<T> set = new HashSet<>();
            for (T each : all) {
                if (!set.add(each)) {
                    return true;
                }
            }
        }
        return false;
    }

}
