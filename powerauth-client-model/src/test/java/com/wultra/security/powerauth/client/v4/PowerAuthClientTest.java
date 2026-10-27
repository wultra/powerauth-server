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

import com.wultra.security.powerauth.client.model.request.v4.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Test of the convenience methods of {@link PowerAuthClient}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class PowerAuthClientTest {

    @Test
    void statusWithoutBlobSendsNeitherBlobNorDevicePublicKeys() throws Exception {
        final List<GetActivationStatusRequest> sent = new ArrayList<>();
        final GetActivationStatusResponse response = new GetActivationStatusResponse();
        final PowerAuthClient client = clientCapturing(sent, response);

        final GetActivationStatusResponse result = client.getActivationStatusWithoutBlob("activation-id");

        assertSame(response, result);
        assertEquals(1, sent.size());
        assertEquals("activation-id", sent.get(0).getActivationId());
        assertFalse(sent.get(0).isIncludeStatusBlob());
        assertFalse(sent.get(0).isIncludeDevicePublicKeys());
    }

    private static PowerAuthClient clientCapturing(final List<GetActivationStatusRequest> sent, final GetActivationStatusResponse response) {
        final InvocationHandler handler = (proxy, method, args) -> {
            if (method.isDefault()) {
                return InvocationHandler.invokeDefault(proxy, method, args);
            }
            sent.add((GetActivationStatusRequest) args[0]);
            return response;
        };
        return (PowerAuthClient) Proxy.newProxyInstance(PowerAuthClient.class.getClassLoader(), new Class<?>[]{PowerAuthClient.class}, handler);
    }

}
