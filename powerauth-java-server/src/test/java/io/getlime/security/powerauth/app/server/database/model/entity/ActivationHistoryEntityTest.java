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
package io.getlime.security.powerauth.app.server.database.model.entity;

import lombok.extern.slf4j.Slf4j;
import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

/**
 * Test for {@link ActivationHistoryEntity}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Slf4j
class ActivationHistoryEntityTest {

    @Test
    void testEqualsContract() {
        final ApplicationEntity application1 = new ApplicationEntity();
        application1.setId("app1");
        final ApplicationEntity application2 = new ApplicationEntity();
        application2.setId("app2");

        final ApplicationVersionEntity applicationVersion1 = new ApplicationVersionEntity();
        applicationVersion1.setId("v1");
        final ApplicationVersionEntity applicationVersion2 = new ApplicationVersionEntity();
        applicationVersion2.setId("v2");

        final ActivationHistoryEntity activationHistory1 = new ActivationHistoryEntity();
        activationHistory1.setTimestampCreated(new Date(1));
        final ActivationHistoryEntity activationHistory2 = new ActivationHistoryEntity();
        activationHistory2.setTimestampCreated(new Date(2));

        EqualsVerifier.forClass(ActivationHistoryEntity.class)
                .withOnlyTheseFields("activation", "timestampCreated")
                // TODO (racansky, 2023-11-09) equals and hashCode is using getActivation().getActivationId() but still getting false positive; https://jqno.nl/equalsverifier/manual/jpa-entities/
                .suppress(Warning.JPA_GETTER)
                .withPrefabValues(ApplicationEntity.class, application1, application2)
                .withPrefabValues(ApplicationVersionEntity.class, applicationVersion1, applicationVersion2)
                .withPrefabValues(List.class, List.of(activationHistory1), List.of(activationHistory2))
                .verify();
    }
}
