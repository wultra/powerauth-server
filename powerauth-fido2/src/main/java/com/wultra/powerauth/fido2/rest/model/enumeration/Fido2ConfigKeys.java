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
 *
 */

package com.wultra.powerauth.fido2.rest.model.enumeration;

/**
 * FIDO2 configuration key strings.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public final class Fido2ConfigKeys {

    public static final String CONFIG_KEY_ALLOWED_ATTESTATION_FMT = "fido2_attestation_fmt_allowed";
    public static final String CONFIG_KEY_ALLOWED_AAGUIDS = "fido2_aaguids_allowed";
    public static final String CONFIG_KEY_ROOT_CA_CERTS = "fido2_root_ca_certs";

}
