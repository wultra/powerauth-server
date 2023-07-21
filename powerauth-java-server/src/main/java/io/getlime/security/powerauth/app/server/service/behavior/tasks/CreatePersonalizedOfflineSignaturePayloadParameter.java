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

package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Parameter object for {@link OfflineSignatureServiceBehavior#createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadParameter)}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Builder
@Getter
public class CreatePersonalizedOfflineSignaturePayloadParameter {

    private String activationId;
    private String data;
    private KeyConvertor keyConversionUtilities;
    private String nonce;
    private String proximityCheckSeed;
    private Duration proximityCheckStepLength;
}
