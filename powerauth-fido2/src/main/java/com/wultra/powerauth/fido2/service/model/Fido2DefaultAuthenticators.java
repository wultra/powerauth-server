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

package com.wultra.powerauth.fido2.service.model;

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Class containing map of default FIDO2 AAGUID authenticator identifiers.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
public class Fido2DefaultAuthenticators {

    private static final Set<String> WULTRA_MODELS = Set.of(
            "dca09ba7-4992-4be8-9283-ee98cd6fb529"
    );

    private static final Set<Fido2Authenticator> MODELS = Set.of(
            Fido2Authenticator.create("b93fd961-f2e6-462f-b122-82002247de78", "Android Authenticator with SafetyNet Attestation"),

            // ATKey
            Fido2Authenticator.create("ba76a271-6eb6-4171-874d-b6428dbe3437", "ATKey.ProS"),
            Fido2Authenticator.create("d41f5a69-b817-4144-a13c-9ebd6d9254d6", "ATKey.Card CTAP2.0"),
            Fido2Authenticator.create("e1a96183-5016-4f24-b55b-e3ae23614cc6", "ATKey.Pro CTAP2.0"),
            Fido2Authenticator.create("e416201b-afeb-41ca-a03d-2281c28322aa", "ATKey.Pro CTAP2.1"),

            // Atos
            Fido2Authenticator.create("1c086528-58d5-f211-823c-356786e36140", "Atos CardOS FIDO2"),

            // Crayonic
            Fido2Authenticator.create("be727034-574a-f799-5c76-0929e0430973", "Crayonic KeyVault K1 (USB-NFC-BLE FIDO2 Authenticator)"),

            // Cryptnox
            Fido2Authenticator.create("9c835346-796b-4c27-8898-d6032f515cc5", "Cryptnox FIDO2"),

            // Ensurity
            Fido2Authenticator.create("454e5346-4944-4ffd-6c93-8e9267193e9a", "Ensurity ThinC"),

            // ESS
            Fido2Authenticator.create("5343502d-5343-5343-6172-644649444f32", "ESS Smart Card Inc. Authenticator"),

            // eWBM
            Fido2Authenticator.create("61250591-b2bc-4456-b719-0b17be90bb30", "eWBM eFPA FIDO2 Authenticator"),

            // FEITIAN
            Fido2Authenticator.create("12ded745-4bed-47d4-abaa-e713f51d6393", "AllinPass FIDO"),
            Fido2Authenticator.create("2c0df832-92de-4be1-8412-88a8f074df4a", "FIDO Java Card"),
            Fido2Authenticator.create("310b2830-bd4a-4da5-832e-9a0dfc90abf2", "MultiPass FIDO"),
            Fido2Authenticator.create("3e22415d-7fdf-4ea4-8a0c-dd60c4249b9d", "Feitian iePass FIDO Authenticator"),
            Fido2Authenticator.create("6e22415d-7fdf-4ea4-8a0c-dd60c4249b9d", "iePass FIDO"),
            Fido2Authenticator.create("77010bd7-212a-4fc9-b236-d2ca5e9d4084", "BioPass FIDO"),
            Fido2Authenticator.create("833b721a-ff5f-4d00-bb2e-bdda3ec01e29", "ePassFIDO K10, A4B, K28"),
            Fido2Authenticator.create("8c97a730-3f7b-41a6-87d6-1e9b62bda6f0", "FIDO Fingerprint Card"),
            Fido2Authenticator.create("b6ede29c-3772-412c-8a78-539c1f4c62d2", "BioPass FIDO Plus"),
            Fido2Authenticator.create("ee041bce-25e5-4cdb-8f86-897fd6418464", "ePassFIDO K39, NFC, NFC Plus"),

            // GoTrust
            Fido2Authenticator.create("3b1adb99-0dfe-46fd-90b8-7f7614a4de2a", "GoTrust Idem Key FIDO2 Authenticator"),
            Fido2Authenticator.create("9f0d8150-baa5-4c00-9299-ad62c8bb4e87", "GoTrust Idem Card FIDO2 Authenticator"),

            // HID Global
            Fido2Authenticator.create("54d9fee8-e621-4291-8b18-7157b99c5bec", "HID Crescendo Enabled"),
            Fido2Authenticator.create("692db549-7ae5-44d5-a1e5-dd20a493b723", "HID Crescendo Key"),
            Fido2Authenticator.create("aeb6569c-f8fb-4950-ac60-24ca2bbe2e52", "HID Crescendo C2300"),

            // Hideez
            Fido2Authenticator.create("3e078ffd-4c54-4586-8baa-a77da113aec5", "Hideez Key 3 FIDO2"),
            Fido2Authenticator.create("4e768f2c-5fab-48b3-b300-220eb487752b", "Hideez Key 4 FIDO2 SDK"),

            // Hyper
            Fido2Authenticator.create("9f77e279-a6e2-4d58-b700-31e5943c6a98", "Hyper FIDO Pro"),
            Fido2Authenticator.create("d821a7d4-e97c-4cb6-bd82-4237731fd4be", "Hyper FIDO Bio Security Key"),

            // MKGroup
            Fido2Authenticator.create("f4c63eff-d26c-4248-801c-3736c7eaa93a", "FIDO KeyPass S3"),

            // KEY-ID
            Fido2Authenticator.create("d91c5288-0ef0-49b7-b8ae-21ca0aa6b3f3", "KEY-ID FIDO2 Authenticator"),

            // NEOWAVE
            Fido2Authenticator.create("3789da91-f943-46bc-95c3-50ea2012f03a", "NEOWAVE Winkeo FIDO2"),
            Fido2Authenticator.create("c5703116-972b-4851-a3e7-ae1259843399", "NEOWAVE Badgeo FIDO2"),

            // NXP Semiconductors
            Fido2Authenticator.create("07a9f89c-6407-4594-9d56-621d5f1e358b", "NXP Semiconductors FIDO2 Conformance Testing CTAP2 Authenticator"),

            // OCTATCO
            Fido2Authenticator.create("a1f52be5-dfab-4364-b51c-2bd496b14a56", "OCTATCO EzFinger2 FIDO2 AUTHENTICATOR"),
            Fido2Authenticator.create("bc2fe499-0d8e-4ffe-96f3-94a82840cf8c", "OCTATCO EzQuant FIDO2 AUTHENTICATOR"),

            // OneSpan
            Fido2Authenticator.create("30b5035e-d297-4fc1-b00b-addc96ba6a97", "OneSpan FIDO Touch"),

            // Precision InnaIT
            Fido2Authenticator.create("88bbd2f0-342a-42e7-9729-dd158be5407a", "Precision InnaIT Key FIDO 2 Level 2 certified"),

            // SmartDisplayer
            Fido2Authenticator.create("516d3969-5a57-5651-5958-4e7a49434167", "SmartDisplayer BobeePass (NFC-BLE FIDO2 Authenticator)"),

            // Solo
            Fido2Authenticator.create("8876631b-d4a0-427f-5773-0ec71c9e0279", "Solo Secp256R1 FIDO2 CTAP2 Authenticator"),
            Fido2Authenticator.create("8976631b-d4a0-427f-5773-0ec71c9e0279", "Solo Tap Secp256R1 FIDO2 CTAP2 Authenticator"),

            // Somu
            Fido2Authenticator.create("9876631b-d4a0-427f-5773-0ec71c9e0279", "Somu Secp256R1 FIDO2 CTAP2 Authenticator"),

            // Swissbit
            Fido2Authenticator.create("931327dd-c89b-406c-a81e-ed7058ef36c6", "Swissbit iShield FIDO2"),

            // Thales
            Fido2Authenticator.create("b50d5e0a-7f81-4959-9b12-f45407407503", "Thales IDPrime MD 3940 FIDO"),
            Fido2Authenticator.create("efb96b10-a9ee-4b6c-a4a9-d32125ccd4a4", "Thales eToken FIDO"),

            // TrustKey
            Fido2Authenticator.create("95442b2e-f15e-4def-b270-efb106facb4e", "TrustKey G310(H)"),
            Fido2Authenticator.create("87dbc5a1-4c94-4dc8-8a47-97d800fd1f3c", "TrustKey G320(H)"),
            Fido2Authenticator.create("da776f39-f6c8-4a89-b252-1d86137a46ba", "TrustKey T110"),
            Fido2Authenticator.create("e3512a8a-62ae-11ea-bc55-0242ac130003", "TrustKey T120"),

            // TOKEN2
            Fido2Authenticator.create("ab32f0c6-2239-afbb-c470-d2ef4e254db7", "TOKEN2 FIDO2 Security Key"),

            // uTrust
            Fido2Authenticator.create("73402251-f2a8-4f03-873e-3cb6db604b03", "uTrust FIDO2 Security Key"),

            // Vancosys
            Fido2Authenticator.create("39a5647e-1853-446c-a1f6-a79bae9f5bc7", "Vancosys Android Authenticator"),
            Fido2Authenticator.create("820d89ed-d65a-409e-85cb-f73f0578f82a", "Vancosys iOS Authenticator"),

            // VinCSS
            Fido2Authenticator.create("5fdb81b8-53f0-4967-a881-f5ec26fe4d18", "VinCSS FIDO2 Authenticator"),

            // VivoKey
            Fido2Authenticator.create("d7a423ad-3e19-4492-9200-78137dccc136", "VivoKey Apex FIDO2"),

            // Windows Hello
            Fido2Authenticator.create("08987058-cadc-4b81-b6e1-30de50dcbe96", "Windows Hello Hardware Authenticator"),
            Fido2Authenticator.create("6028b017-b1d4-4c02-b4b3-afcdafc96bb2", "Windows Hello Software Authenticator"),
            Fido2Authenticator.create("9ddd1817-af5a-4672-a2b9-3e3dd95000a9", "Windows Hello VBS Hardware Authenticator"),

            // WiSECURE
            Fido2Authenticator.create("504d7149-4e4c-3841-4555-55445a677357", "WiSECURE AuthTron USB FIDO2 Authenticator"),

            // Wultra
            Fido2Authenticator.create("dca09ba7-4992-4be8-9283-ee98cd6fb529", "Wultra Authenticator 1", SignatureType.POSSESSION_KNOWLEDGE),

            // Yubico
            Fido2Authenticator.create("0bb43545-fd2c-4185-87dd-feb0b2916ace", "Security Key NFC by Yubico - Enterprise Edition"),
            Fido2Authenticator.create("149a2021-8ef6-4133-96b8-81f8d5b7f1f5", "Security Key by Yubico with NFC"),
            Fido2Authenticator.create("2fc0579f-8113-47ea-b116-bb5a8db9202a", "YubiKey 5 Series with NFC"),
            Fido2Authenticator.create("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73", "Security Key by Yubico with NFC"),
            Fido2Authenticator.create("73bb0cd4-e502-49b8-9c6f-b59445bf720b", "YubiKey 5 FIPS Series"),
            Fido2Authenticator.create("85203421-48f9-4355-9bc8-8a53846e5083", "YubiKey 5Ci FIPS"),
            Fido2Authenticator.create("a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa", "Security Key by Yubico with NFC"),
            Fido2Authenticator.create("b92c3f9a-c014-4056-887f-140a2501163b", "Security Key by Yubico"),
            Fido2Authenticator.create("c1f9a0bc-1dd2-404a-b27f-8e29047a43fd", "YubiKey 5 FIPS Series with NFC"),
            Fido2Authenticator.create("c5ef55ff-ad9a-4b9f-b580-adebafe026d0", "YubiKey 5Ci"),
            Fido2Authenticator.create("cb69481e-8ff7-4039-93ec-0a2729a154a8", "YubiKey 5 Series"),
            Fido2Authenticator.create("d8522d9f-575b-4866-88a9-ba99fa02f35b", "YubiKey Bio Series"),
            Fido2Authenticator.create("ee882879-721c-4913-9775-3dfcce97072a", "YubiKey 5 Series"),
            Fido2Authenticator.create("f8a011f3-8c0a-4d15-8006-17111f9edc7d", "Security Key by Yubico"),
            Fido2Authenticator.create("fa2b99dc-9e39-4257-8f92-4a30d23c4118", "YubiKey 5 Series with NFC"),
            Fido2Authenticator.create("34f5766d-1536-4a24-9033-0e294e510fb0", "YubiKey 5 Series CTAP2.1 Preview Expired"),
            Fido2Authenticator.create("83c47309-aabb-4108-8470-8be838b573cb", "YubiKey Bio Series (Enterprise Profile)"),

            // Other authenticators
            Fido2Authenticator.create("ad784498-1902-3f54-b99a-10bb7dbd9588", "Apple MacBook Pro 14-inch, 2021"),
            Fido2Authenticator.create("4ae71336-e44b-39bf-b9d2-752e234818a5", "Apple Passkeys")
    );

    private static final Map<UUID, Fido2Authenticator> MODEL_MAP = MODELS.stream()
            .collect(Collectors.toMap(Fido2Authenticator::aaguid, Function.identity()));

    private Fido2DefaultAuthenticators() {
        throw new IllegalStateException("Should not be instantiated");
    }

    public static Optional<Fido2Authenticator> findByAaguid(final UUID aaguid) {
        return Optional.ofNullable(MODEL_MAP.get(aaguid));
    }

    public static boolean isWultraModel(final String aaguid) {
        return WULTRA_MODELS.contains(aaguid);
    }

}
