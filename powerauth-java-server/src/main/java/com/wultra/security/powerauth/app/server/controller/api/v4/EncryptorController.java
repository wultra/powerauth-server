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

package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.EncryptionBehaviorAead;
import com.wultra.security.powerauth.client.model.request.v4.ExtractEncryptorRequest;
import com.wultra.security.powerauth.client.model.response.v4.ExtractEncryptorResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to encryptor shared secret initialization.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("encryptorControllerV4")
@RequestMapping("/rest/v4/encryptor")
@Tag(name = "PowerAuth Encryptor Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class EncryptorController {

    private final EncryptionBehaviorAead service;

    /**
     * Create AEAD encryptor.
     *
     * @param request Prepare the AEAD encryptor for given request.
     * @return Response with AEAD encryptor parameters.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping
    public ObjectResponse<ExtractEncryptorResponse> extractEncryptor(@Valid @RequestBody ObjectRequest<ExtractEncryptorRequest> request) throws Exception {
        final ExtractEncryptorRequest req = request.getRequestObject();
        logger.info("action: getEncryptor, state: initiated, applicationKey: {}", req.getApplicationKey());
        logger.debug("action: getEncryptor, state: initiated, request: {}", request);
        final ObjectResponse<ExtractEncryptorResponse> response = new ObjectResponse<>(service.extractEncryptor(req));
        logger.info("action: getEncryptor, state: succeeded");
        logger.debug("action: getEncryptor, state: succeeded, response: {}", response);
        return response;
    }

}
