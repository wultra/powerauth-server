/*
 * Copyright 2017 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.app.admin.security;

/**
 * Helper class that determines which security method is used.
 *
 * Currently, only LDAP is supported.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class SecurityMethod {

    /**
     * Authentication via LDAP.
     */
    public static final String LDAP = "ldap";

    /**
     * Checks if a provided security method is LDAP authentication.
     * @param securityMethod Security method to be tested.
     * @return True in case given method represents LDAP authentication, false otherwise.
     */
    public static boolean isLdap(String securityMethod) {
        return securityMethod != null && securityMethod
                .trim()
                .toLowerCase()
                .equals(LDAP);
    }
}
