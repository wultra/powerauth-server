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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.client.v3.SignatureType;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.SignatureEntity;
import io.getlime.security.powerauth.app.server.service.model.signature.OnlineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureResponse;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;

import javax.persistence.EntityManager;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for {@link SignatureSharedServiceBehavior}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest
class SignatureSharedServiceBehaviorTest {

    @Autowired
    private SignatureSharedServiceBehavior tested;

    @Autowired
    private EntityManager entityManager;

    @Sql
    @Test
    void testHandleValidSignature() {
        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");
        final SignatureResponse signatureResponse = new SignatureResponse(true, 1L, new byte[]{'x'}, 3, SignatureType.POSSESSION_KNOWLEDGE);
        final byte[] data = Base64.getDecoder().decode("UE9TVCZMM0JoTDNOcFoyNWhkSFZ5WlM5MllXeHBaR0YwWlE9PSYyaVR6Ry9CMzVRSmY3SHhaZmNseUZnPT0mUVd4c0lIbHZkWElnWW1GelpTQmhjbVVnWW1Wc2IyNW5JSFJ2SUhWeklRPT0mbzk3MGdVQkx2d0NUZGJJT1BrWjBsdz09");
        final SignatureData signatureData = new SignatureData(data, "39319618-09892741", SignatureConfiguration.decimal(), "3.0", null, 3);
        final OnlineSignatureRequest onlineSignatureRequest = new OnlineSignatureRequest(signatureData, SignatureType.POSSESSION_KNOWLEDGE);
        final Date currentTimestamp = new Date();

        assertEquals(0, activation.getCounter());
        assertEquals("D5XibWWPCv+nOOfcdfnUGQ==", activation.getCtrDataBase64());

        tested.handleValidSignature(activation, signatureResponse, onlineSignatureRequest, currentTimestamp);

        assertEquals(1, activation.getCounter());
        assertEquals("eA==", activation.getCtrDataBase64());

        final SignatureEntity signatureEntity = entityManager.createQuery("select s from SignatureEntity s where s.activation =: activation", SignatureEntity.class)
                .setParameter("activation", activation)
                .getResultList().stream()
                    .findFirst()
                    .orElseThrow(() -> new AssertionFailedError("No SignatureEntity found"));

        assertEquals(0, signatureEntity.getActivationCounter());
        assertEquals("D5XibWWPCv+nOOfcdfnUGQ==", signatureEntity.getActivationCtrDataBase64());
    }
}
