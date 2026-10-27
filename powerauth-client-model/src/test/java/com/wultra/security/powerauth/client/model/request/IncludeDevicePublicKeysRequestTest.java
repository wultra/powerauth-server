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
package com.wultra.security.powerauth.client.model.request;

import com.wultra.security.powerauth.client.model.request.v4.GetActivationStatusRequest;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of the opt-in device public keys flag on activation requests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class IncludeDevicePublicKeysRequestTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    @Test
    void activationListRequestDoesNotIncludeKeysByDefault() {
        assertFalse(new GetActivationListForUserRequest().isIncludeDevicePublicKeys());
    }

    @Test
    void activationListRequestWithoutFlagDeserializesToNoKeys() {
        final GetActivationListForUserRequest request = MAPPER.readValue("{\"userId\":\"user\"}", GetActivationListForUserRequest.class);

        assertFalse(request.isIncludeDevicePublicKeys());
    }

    @Test
    void activationListRequestDeserializesExplicitFlag() {
        final GetActivationListForUserRequest request = MAPPER.readValue("{\"userId\":\"user\",\"includeDevicePublicKeys\":true}", GetActivationListForUserRequest.class);

        assertTrue(request.isIncludeDevicePublicKeys());
    }

    @Test
    void lookupRequestDoesNotIncludeKeysByDefault() {
        assertFalse(new LookupActivationsRequest().isIncludeDevicePublicKeys());
    }

    @Test
    void lookupRequestWithoutFlagDeserializesToNoKeys() {
        final LookupActivationsRequest request = MAPPER.readValue("{\"userIds\":[\"user\"]}", LookupActivationsRequest.class);

        assertFalse(request.isIncludeDevicePublicKeys());
    }

    @Test
    void lookupRequestDeserializesExplicitFlag() {
        final LookupActivationsRequest request = MAPPER.readValue("{\"userIds\":[\"user\"],\"includeDevicePublicKeys\":true}", LookupActivationsRequest.class);

        assertTrue(request.isIncludeDevicePublicKeys());
    }

    @Test
    void statusRequestDoesNotIncludeKeysByDefault() {
        final GetActivationStatusRequest request = new GetActivationStatusRequest();

        assertFalse(request.isIncludeDevicePublicKeys());
        assertTrue(request.isIncludeStatusBlob());
    }

    @Test
    void statusRequestWithoutFlagKeepsBlobSettingAndDeserializesToNoKeys() {
        final GetActivationStatusRequest request = MAPPER.readValue("{\"activationId\":\"id\",\"includeStatusBlob\":false}", GetActivationStatusRequest.class);

        assertFalse(request.isIncludeStatusBlob());
        assertFalse(request.isIncludeDevicePublicKeys());
    }

    @Test
    void statusRequestKeepsKeysAndBlobFlagsIndependent() {
        final GetActivationStatusRequest request = MAPPER.readValue("{\"activationId\":\"id\",\"includeStatusBlob\":false,\"includeDevicePublicKeys\":true}", GetActivationStatusRequest.class);

        assertFalse(request.isIncludeStatusBlob());
        assertTrue(request.isIncludeDevicePublicKeys());
    }

}
