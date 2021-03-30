/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server;

import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import io.getlime.security.powerauth.app.server.service.PowerAuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for creating application entity.
 *
 * @author Lukas Lukovsky, lukas.lukovsky@gmail.com
 */
@SpringBootTest
@ExtendWith(SpringExtension.class)
public class CreateApplicationTest {

    private PowerAuthService powerAuthService;

    @Autowired
    public void setPowerAuthService(PowerAuthService powerAuthService) {
        this.powerAuthService = powerAuthService;
    }

    @Test
    public void testCreateApplicationWithDuplicateName() {
        String testId = UUID.randomUUID().toString();
        CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(testId);
        assertDoesNotThrow(()-> powerAuthService.createApplication(request));
        assertThrows(DataIntegrityViolationException.class, ()-> powerAuthService.createApplication(request));
    }

}
