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
 *
 */
package com.wultra.security.powerauth.client.v4;

import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.v4.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Test of the convenience methods of {@link PowerAuthClient}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class PowerAuthClientTest {

    @Test
    void statusWithoutBlobSendsNeitherBlobNorDevicePublicKeys() throws PowerAuthClientException {
        final PowerAuthClient client = mock(PowerAuthClient.class, CALLS_REAL_METHODS);
        final GetActivationStatusResponse response = new GetActivationStatusResponse();
        doReturn(response).when(client).getActivationStatus(any(GetActivationStatusRequest.class));

        final GetActivationStatusResponse result = client.getActivationStatusWithoutBlob("activation-id");

        assertSame(response, result);
        final ArgumentCaptor<GetActivationStatusRequest> captor = ArgumentCaptor.forClass(GetActivationStatusRequest.class);
        verify(client).getActivationStatus(captor.capture());
        final GetActivationStatusRequest sent = captor.getValue();
        assertEquals("activation-id", sent.getActivationId());
        assertFalse(sent.isIncludeStatusBlob());
        assertFalse(sent.isIncludeDevicePublicKeys());
    }

}
