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
package io.getlime.security.powerauth.app.server.service.fido2;

import com.wultra.powerauth.fido2.rest.model.converter.AssertionChallengeConverter;
import com.wultra.security.powerauth.client.model.request.OperationDetailRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.fido2.model.request.AssertionChallengeRequest;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OperationServiceBehavior;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Test for {@link PowerAuthAssertionProvider}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class PowerAuthAssertionProviderTest {

    @Mock
    private OperationServiceBehavior operationServiceBehavior;

    @Mock
    private AssertionChallengeConverter assertionChallengeConverter;

    @InjectMocks
    private PowerAuthAssertionProvider tested;

    @Test
    void testProvideChallengeForAssertion() throws Exception {
        final AssertionChallengeRequest request = new AssertionChallengeRequest();

        tested.provideChallengeForAssertion(request);

        verify(operationServiceBehavior, never()).operationDetail(any());
    }

    @Test
    void testProvideChallengeForAssertion_operationId() throws Exception {
        final AssertionChallengeRequest challengeRequest = new AssertionChallengeRequest();
        challengeRequest.setOperationId("c38ea166-233b-436a-8658-9a84e73967c3");

        final OperationDetailRequest operationRequest = new OperationDetailRequest();
        operationRequest.setOperationId("c38ea166-233b-436a-8658-9a84e73967c3");

        when(operationServiceBehavior.operationDetail(operationRequest))
                .thenReturn(new OperationDetailResponse());

        tested.provideChallengeForAssertion(challengeRequest);

        verify(operationServiceBehavior, never()).createOperation(any());
        verify(operationServiceBehavior).operationDetail(operationRequest);
    }
}