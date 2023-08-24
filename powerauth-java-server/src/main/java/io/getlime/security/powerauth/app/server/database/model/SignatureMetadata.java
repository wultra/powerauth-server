package io.getlime.security.powerauth.app.server.database.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignatureMetadata {

    private String signatureDataMethod;

    private String signatureDataUriId;
}
