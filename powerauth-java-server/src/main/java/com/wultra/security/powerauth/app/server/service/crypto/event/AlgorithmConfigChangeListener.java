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
 *
 */

package com.wultra.security.powerauth.app.server.service.crypto.event;

import com.wultra.security.powerauth.app.server.service.crypto.MasterKeyGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Algorithm configuration change listener.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class AlgorithmConfigChangeListener {

    private final MasterKeyGenerationService masterKeyGenerationService;

    @EventListener
    public void onAlgorithmConfigChanged(AlgorithmConfigChangedEvent event) {
        try {
            masterKeyGenerationService.generateMasterKeyPairs(event.getApplication());
        } catch (GenericServiceException e) {
            logger.error("Unable to generate master key pairs", e);
        }
    }
}