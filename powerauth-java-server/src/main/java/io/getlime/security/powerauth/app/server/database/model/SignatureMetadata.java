package io.getlime.security.powerauth.app.server.database.model;


public interface SignatureMetadata<T1, T2> {

    T1 getMetadataParam1();

    void setMetadataParam1(T1 metadataParam1);

    T2 getMetadataParam2();

    void setMetadataParam2(T2 metadataParam2);

}
