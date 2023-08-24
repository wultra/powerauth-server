package io.getlime.security.powerauth.app.server.database.model;

import lombok.Data;

@Data
public class SignatureMetadata {

    private String signatureDataMethod;

    private String signatureDataUriId;
}
