package io.getlime.security.powerauth.app.server.database.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class PowerAuthSignatureMetadata implements SignatureMetadata<String, String> {

    private String signatureDataMethod;

    private String signatureDataUriId;


    @Override
    public String getMetadataParam1() {
        return signatureDataMethod;
    }

    @Override
    public void setMetadataParam1(String metadataParam1) {
        this.signatureDataMethod = metadataParam1;
    }

    @Override
    public String getMetadataParam2() {
        return signatureDataUriId;
    }

    @Override
    public void setMetadataParam2(String metadataParam2) {
        this.signatureDataUriId = metadataParam2;
    }
}
