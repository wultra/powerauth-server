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

package io.getlime.security.powerauth.app.server.service.callbacks.model;

import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Convertor between data classes related to Callbacks URL.
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CallbackUrlConvertor {

    public static CallbackUrlEvent convert(final CallbackUrlEventEntity callbackUrlEventEntity) {
        return CallbackUrlEvent.builder()
                .callbackUrlEventEntityId(callbackUrlEventEntity.getId())
                .callbackData(callbackUrlEventEntity.getCallbackData())
                .callbackUrl(callbackUrlEventEntity.getCallbackUrlEntity().getCallbackUrl())
                .restClientCacheKey(callbackUrlEventEntity.getCallbackUrlEntity().getId())
                .status(callbackUrlEventEntity.getStatus())
                .idempotencyKey(callbackUrlEventEntity.getIdempotencyKey())
                .build();
    }

}
