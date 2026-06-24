/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.persistence.ConfigStoreService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;

/**
 * Test for {@link ActivationRemoveServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ActivationRemoveServiceBehaviorTest {

    private static final String ACTIVATION_ID = "e43a5dec-afea-4a10-a80b-b2183399f16b";
    private static final String EXTERNAL_USER_ID = "operator-1";

    @Mock
    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    @Mock
    private ActivationQueryService activationQueryService;

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private CallbackUrlBehavior callbackUrlBehavior;

    @Mock
    private ConfigStoreService configStoreService;

    @InjectMocks
    private ActivationRemoveServiceBehavior tested;

    @Test
    void testRemoveActivation_setsRemovedStatusAndPurgesPerDeviceConfig() {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setActivationId(ACTIVATION_ID);
        activation.setActivationStatus(ActivationStatus.ACTIVE);

        tested.removeActivation(activation, EXTERNAL_USER_ID);

        assertEquals(ActivationStatus.REMOVED, activation.getActivationStatus());
        verify(activationHistoryServiceBehavior).saveActivationAndLogChange(activation, EXTERNAL_USER_ID);
        verify(configStoreService).deleteByActivationId(ACTIVATION_ID);
        verify(callbackUrlBehavior).notifyCallbackListenersOnActivationChange(activation);
    }
}
