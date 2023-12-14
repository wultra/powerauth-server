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
package io.getlime.security.powerauth.app.server.service;

import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for {@link PowerAuthService}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest
@Transactional
@ActiveProfiles("test")
class PowerAuthServiceTest {

    @Autowired
    private PowerAuthService tested;

    @Test
    @Sql
    void testGetActivationListForUser() throws Exception {
        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId("user1");

        final List<Activation> result = tested.getActivationListForUser(request).getActivations();

        assertEquals(3, result.size());

        final List<String> expectedIdOrder = List.of("e43a5dec-afea-4a10-a80b-b2183399f16b", "47cf47b3-c72d-4859-a5f4-51da6d6ad6a3", "0d34cfc4-af98-4eb8-aba5-58f766bd2967");
        final List<String> actualIdOrder = result.stream().map(Activation::getActivationId).toList();
        assertEquals(expectedIdOrder, actualIdOrder);

        final Date timestampCreated1 = result.get(0).getTimestampCreated();
        final Date timestampCreated2 = result.get(1).getTimestampCreated();
        final Date timestampCreated3 = result.get(2).getTimestampCreated();
        assertEquals(1, timestampCreated1.compareTo(timestampCreated2));
        assertEquals(1, timestampCreated2.compareTo(timestampCreated3));
    }
}