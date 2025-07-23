/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.service.util.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * JWS algorithm name used in the {@code alg} header when the ML-DSA algorithm is used for signing.
 * This class exists due to missing support of the algorithm name in the {@link JWSAlgorithm} list.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JWSAlgorithmMLDSA {

    public static final JWSAlgorithm MLDSA65 = new JWSAlgorithm("ML-DSA-65");

}
