/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.client.model.entity.fido2;

import lombok.*;
import lombok.extern.jackson.Jacksonized;

import java.util.Collections;
import java.util.List;

/**
 * Representation of an allowed authenticator instance.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Getter
@EqualsAndHashCode
@ToString
@Builder
@Jacksonized
public class AllowCredentials {

    private final byte[] credentialId;

    /**
     * Currently one credential type is defined, namely {@code public-key}.
     *
     * @see <a href="https://www.w3.org/TR/webauthn-2/#enum-credentialType">W3C WebAuthn specification</a>
     */
    @Builder.Default
    private final String type = "public-key";

    @Builder.Default
    private final List<String> transports = Collections.emptyList();

}
