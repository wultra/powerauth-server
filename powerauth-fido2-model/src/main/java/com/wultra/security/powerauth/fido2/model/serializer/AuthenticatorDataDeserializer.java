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

package com.wultra.security.powerauth.fido2.model.serializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorData;
import com.wultra.security.powerauth.fido2.model.entity.ECPoint;
import com.wultra.security.powerauth.fido2.model.entity.Flags;
import com.wultra.security.powerauth.fido2.model.entity.PublicKeyObject;
import com.wultra.security.powerauth.fido2.model.enumeration.CurveType;
import com.wultra.security.powerauth.fido2.model.enumeration.ECKeyType;
import com.wultra.security.powerauth.fido2.model.enumeration.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.Serial;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * JSON deserializer for FIDO2 {@link AuthenticatorData}.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Slf4j
public class AuthenticatorDataDeserializer extends StdDeserializer<AuthenticatorData> {

    @Serial
    private static final long serialVersionUID = -7644582864083436208L;

    private final CBORMapper cborMapper = new CBORMapper();

    /**
     * No-arg deserializer constructor.
     */
    public AuthenticatorDataDeserializer() {
        this(null);
    }

    /**
     * Deserializer constructor with value class parameter.
     * @param vc Value class parameter.
     */
    public AuthenticatorDataDeserializer(Class<?> vc) {
        super(vc);
    }

    /**
     * Deserialized the FIDO2 authenticator data.
     * @param jsonParser JSON parser.
     * @param deserializationContext Deserialization context.
     * @return Deserialized FIDO2 authenticator data.
     * @throws Fido2DeserializationException Thrown in case JSON deserialization fails.
     */
    @Override
    public AuthenticatorData deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws Fido2DeserializationException {
        try {
            final AuthenticatorData result = new AuthenticatorData();

            // Serialize Auth Data
            final byte[] authData = jsonParser.getBinaryValue();
            if (authData == null) {
                throw new Fido2DeserializationException("JSON binary value deserialized into null.");
            }
            result.setEncoded(authData);

            // Get RP ID Hash
            final byte[] rpIdHash = new byte[32];
            System.arraycopy(authData, 0, rpIdHash, 0, 32);
            result.setRpIdHash(rpIdHash);

            // Get Flags
            final byte flagByte = authData[32];
            final Flags flags = result.getFlags();

            flags.setUserPresent(isFlagOn(flagByte, 0));
            flags.setReservedBit2(isFlagOn(flagByte, 1));
            flags.setUserVerified(isFlagOn(flagByte, 2));
            flags.setBackupEligible(isFlagOn(flagByte, 3));
            flags.setBackupState(isFlagOn(flagByte, 4));
            flags.setReservedBit6(isFlagOn(flagByte, 5));
            flags.setAttestedCredentialsIncluded(isFlagOn(flagByte, 6));
            flags.setExtensionDataIncluded(isFlagOn(flagByte, 7));

            // Get Signature Counter
            final byte[] signCountBytes = new byte[4];
            System.arraycopy(authData, 33, signCountBytes, 0, 4);
            final int signCount = ByteBuffer.wrap(signCountBytes).getInt(); // big-endian by default
            result.setSignCount(signCount);

            if (authData.length > 37) { // get info about the credentials

                // Get AAGUID
                final byte[] aaguid = new byte[16];
                System.arraycopy(authData, 37, aaguid, 0, 16);
                result.getAttestedCredentialData().setAaguid(aaguid);

                // Get credential ID length
                final byte[] credentialIdLength = new byte[2];
                System.arraycopy(authData, 53, credentialIdLength, 0, 2);
                final ByteBuffer wrapped = ByteBuffer.wrap(credentialIdLength); // big-endian by default
                short credentialIdLengthValue = wrapped.getShort();

                // Get credentialId
                final byte[] credentialId = new byte[credentialIdLengthValue];
                System.arraycopy(authData, 55, credentialId, 0, credentialIdLengthValue);
                result.getAttestedCredentialData().setCredentialId(credentialId);

                // Get credentialPublicKey
                final int remainingLength = authData.length - (55 + credentialIdLengthValue);
                final byte[] credentialPublicKey = new byte[remainingLength];
                System.arraycopy(authData, 55 + credentialIdLengthValue, credentialPublicKey, 0, remainingLength);
                final Map<String, Object> credentialPublicKeyMap = cborMapper.readValue(credentialPublicKey, new TypeReference<>() {});
                if (credentialPublicKeyMap == null) {
                    throw new Fido2DeserializationException("JSON credentialPublicKey deserialized into null.");
                }

                final PublicKeyObject publicKeyObject = new PublicKeyObject();
                final Integer algorithm = (Integer) credentialPublicKeyMap.get("3");
                if (algorithm != null && -7 == algorithm) {
                    publicKeyObject.setAlgorithm(SignatureAlgorithm.ES256);
                } else {
                    throw new RuntimeException("Unsupported algorithm: " + algorithm);
                }
                final Integer curveType = (Integer) credentialPublicKeyMap.get("-1");
                if (curveType != null && 1 == curveType) {
                    publicKeyObject.setCurveType(CurveType.P256);
                } else {
                    throw new RuntimeException("Unsupported curve type: " + curveType);
                }
                final Integer keyType = (Integer) credentialPublicKeyMap.get("1");
                if (keyType != null && 2 == keyType) {
                    publicKeyObject.setKeyType(ECKeyType.UNCOMPRESSED);
                } else {
                    throw new RuntimeException("Unsupported key type: " + keyType);
                }

                final byte[] xBytes = (byte[]) credentialPublicKeyMap.get("-2");
                final byte[] yBytes = (byte[]) credentialPublicKeyMap.get("-3");
                final ECPoint point = new ECPoint();
                point.setX(xBytes);
                point.setY(yBytes);
                publicKeyObject.setPoint(point);

                result.getAttestedCredentialData().setPublicKeyObject(publicKeyObject);
            }
            return result;
        } catch (IOException e) {
            logger.debug(e.getMessage(), e);
            throw new Fido2DeserializationException(e.getMessage(), e);
        }
    }

    private boolean isFlagOn(byte flags, int position) throws IOException {
        if (position < 0 || position > 7) {
            throw new IOException("Invalid position for flag: " + position);
        }
        return ((flags >> position) & 1) == 1;
    }

}
