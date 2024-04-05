/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.wultra.powerauth.fido2.rest.model.entity.AttestationObject;
import com.wultra.powerauth.fido2.rest.model.enumeration.AttestationType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test for {@link AttestationObjectDeserializer}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class AttestationObjectDeserializerTest {

    @Test
    void testDeserialize() throws Exception {
        final String source = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgSSNIkclrzRsyeCBzupzv9viwJm6blgBxWr5qlPop+hMCIDhEwo9C/c3zrp4t6qsw3QZctLMmPCSMsxLsjXv/1s+nY3g1Y4JZAaMwggGfMIIBRKADAgECAgEBMAoGCCqGSM49BAMCMEwxEjAQBgNVBAoMCVNoYXJwTGFiLjE2MDQGA1UEAwwtc3ByaW5nLXNlY3VyaXR5LXdlYmF1dGhuIHRlc3QgaW50ZXJtZWRpYXRlIENBMCAXDTAwMDEwMTAwMDAwMFoYDzI5OTkxMjMxMjM1OTU5WjBjMQswCQYDVQQGEwJVUzESMBAGA1UEChMJU2hhcnBMYWIuMRwwGgYDVQQDExNEdW1teSBBdXRoZW50aWNhdG9yMSIwIAYDVQQLExlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiGTwP+WVdoDVnO4ELphOHP+4EHzmBKbaPkxNQo+5wFXzSn/t6PoZcNvs+13UGwJ9Ch+i5FkndBcdDyztOo9jrzAKBggqhkjOPQQDAgNJADBGAiEAjcvj5exWw64nA9QZRc2EXGipr8dNX/OIbAfFQMlppCICIQCl7ag/uPqTgox/JBSXwO+V+Y2ftsuAaZmSbil7S0k811kB2jCCAdYwggF7oAMCAQICEA0YfqmbKSw+gKpVgNSciIwwCgYIKoZIzj0EAwIwRDESMBAGA1UECgwJU2hhcnBMYWIuMS4wLAYDVQQDDCVzcHJpbmctc2VjdXJpdHktd2ViYXV0aG4gdGVzdCByb290IENBMCAXDTE3MDkyMjAzMTkxMVoYDzIxMTcwODI5MDMxOTExWjBMMRIwEAYDVQQKDAlTaGFycExhYi4xNjA0BgNVBAMMLXNwcmluZy1zZWN1cml0eS13ZWJhdXRobiB0ZXN0IGludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEOLmX8PbauQ7qob93NBaksqfU/j2Ad+Yt3xWoMDZ8QtRkDDo3NjAPnUie9kn+41QmlTW8iiSv7aAOzr67bfWHejRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSk+Its1bZ0fIoRIp40znvmB5LGHTAKBggqhkjOPQQDAgNJADBGAiEAxstgMg9X3ul+fuW7sFIwFX0sCZQZT5Ae1gfrq0MB0pUCIQCv3zynrabpt9bBEc+tzmcb5eZr5M9gp+1YlTLUJOc0eGhhdXRoRGF0YVikANexYfkh9tDjBkTaAF/dyyouYB0YesVvYolcxTs9fxBFAAAAAQAAAAAAAAAAAAAAAAAAAAAAIKJoRphIV4ali+8RRGrFFM4PW0TclZrLQUZ2NfvpCbZGpQECAyYgASFYID8cFAWcJbjXrayfr/H0mBXuijUlJKof3XvSHi3pX+w+IlggSgcCd1PXxb/bJTh1Qj4/8dyKWH1NqDKvhDGM0fjT3y4=";
        final AttestationObject result = AttestationObjectDeserializer.deserialize(source);

        assertNotNull(result);
        assertEquals(source, result.getEncoded());
        assertEquals("packed", result.getFmt());
        assertEquals(AttestationType.BASIC, result.getAttStmt().getAttestationType());
    }
}