package io.getlime.security.powerauth.app.server.database.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureMetadata {

    private String signatureDataMethod;

    private String signatureDataUriId;
}
