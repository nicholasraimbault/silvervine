//! Authentication for the signed portion of a Chrome CRX3 package.

use ring::signature::{UnparsedPublicKey, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY};
use sha2::{Digest, Sha256};

use crate::widevine::download::VerifiedCrx;
use crate::{Error, Result};

const CRX3_FIXED_HEADER_BYTES: usize = 12;
const SIGNATURE_CONTEXT: &[u8; 16] = b"CRX3 SignedData\0";
const MAX_SIGNATURE_HEADER_BYTES: usize = 1024 * 1024;
const RSA_ENCRYPTION_ALGORITHM: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

// DER SubjectPublicKeyInfo carried by the Widevine component's developer-key
// proof. Its SHA-256 begins with the component ID
// `oimompecagnajdejgnnjijobebaeigek`.
const WIDEVINE_COMPONENT_SPKI: &[u8] = &[
    0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xa6, 0x85, 0xef,
    0xb4, 0xd9, 0xc2, 0xcf, 0x3c, 0x05, 0x62, 0x69, 0xeb, 0xe4, 0xfd, 0xfc, 0xce, 0x0c, 0xa5, 0x27,
    0x6f, 0xfc, 0xac, 0x68, 0x07, 0x83, 0xf2, 0x5a, 0x44, 0xf6, 0x9c, 0x22, 0xad, 0x5e, 0x86, 0x60,
    0xe9, 0xbe, 0x9d, 0xa4, 0xe8, 0xef, 0x13, 0xce, 0x0a, 0x1f, 0x2e, 0x8d, 0xc4, 0x7a, 0x47, 0x28,
    0xb5, 0x9c, 0xf4, 0xea, 0xd8, 0x64, 0xc6, 0xd0, 0x2c, 0xaa, 0x74, 0x3c, 0x8e, 0xb1, 0x9d, 0x5a,
    0x44, 0xbb, 0x8c, 0x67, 0x94, 0x2a, 0x5f, 0x77, 0x49, 0xf6, 0x35, 0xe4, 0x95, 0x2d, 0x0b, 0xa8,
    0x67, 0xe8, 0xb2, 0x82, 0x29, 0x19, 0xec, 0x5f, 0xc2, 0x08, 0x1b, 0x88, 0xbb, 0xd0, 0x3a, 0x8f,
    0x50, 0xf8, 0x85, 0x93, 0xac, 0x03, 0xba, 0xdb, 0x42, 0x80, 0xcd, 0x85, 0x34, 0x53, 0xa3, 0x15,
    0xdb, 0xbd, 0x93, 0x24, 0xb4, 0xa6, 0x64, 0xf5, 0x04, 0x15, 0x8e, 0x88, 0x19, 0x02, 0x03, 0x01,
    0x00, 0x01,
];

/// A CRX whose ZIP archive has passed a signature from the pinned Widevine key.
#[derive(Debug)]
pub(super) struct AuthenticatedCrx {
    signed_message: Vec<u8>,
    archive_offset: usize,
}

impl AuthenticatedCrx {
    /// Return the ZIP body covered by the verified component signature.
    pub(super) fn archive(&self) -> &[u8] {
        &self.signed_message[self.archive_offset..]
    }
}

/// Consume manifest-authenticated CRX bytes and verify the Widevine developer
/// signature before any archive member can become executable input.
pub(super) fn authenticate_widevine_crx(crx: VerifiedCrx) -> Result<AuthenticatedCrx> {
    authenticate_crx_with_key(crx.into_bytes(), WIDEVINE_COMPONENT_SPKI)
}

#[cfg(test)]
pub(super) fn trust_unsigned_crx_for_test(crx: VerifiedCrx) -> Result<AuthenticatedCrx> {
    let bytes = crx.into_bytes();
    let archive_offset = crate::widevine::extract::parse_crx3_header(&bytes)?;
    Ok(AuthenticatedCrx {
        signed_message: bytes,
        archive_offset,
    })
}

fn authenticate_crx_with_key(mut crx: Vec<u8>, expected_spki: &[u8]) -> Result<AuthenticatedCrx> {
    let archive_offset = crate::widevine::extract::parse_crx3_header(&crx)?;
    let header = &crx[CRX3_FIXED_HEADER_BYTES..archive_offset];
    if header.len() > MAX_SIGNATURE_HEADER_BYTES {
        return Err(malformed("signature header exceeds the 1 MiB limit"));
    }

    let material = parse_signature_material(header, expected_spki)?;
    let expected_id = Sha256::digest(expected_spki);
    let declared_id = parse_signed_data_id(&material.signed_header_data)?;
    if declared_id != &expected_id[..16] {
        return Err(authentication_failed(
            "signed component ID does not match the pinned Widevine key",
        ));
    }

    let rsa_public_key = rsa_pkcs1_from_spki(expected_spki)?;
    let signed_header_len = u32::try_from(material.signed_header_data.len())
        .map_err(|_| malformed("signed header length exceeds CRX3's u32 encoding"))?;
    let prefix_len = SIGNATURE_CONTEXT
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(material.signed_header_data.len()))
        .ok_or_else(|| malformed("signed message length overflow"))?;
    if prefix_len > archive_offset {
        return Err(malformed(
            "signature proof is too short to contain its signed header",
        ));
    }

    // Reuse the downloaded buffer: move the ZIP body over the now-parsed CRX
    // envelope and write the signature prefix into the reclaimed space. This
    // avoids cloning a package that may be hundreds of MiB.
    let archive_len = crx.len() - archive_offset;
    crx.copy_within(archive_offset.., prefix_len);
    crx.truncate(prefix_len + archive_len);
    crx[..SIGNATURE_CONTEXT.len()].copy_from_slice(SIGNATURE_CONTEXT);
    crx[SIGNATURE_CONTEXT.len()..SIGNATURE_CONTEXT.len() + 4]
        .copy_from_slice(&signed_header_len.to_le_bytes());
    crx[SIGNATURE_CONTEXT.len() + 4..prefix_len].copy_from_slice(&material.signed_header_data);

    UnparsedPublicKey::new(
        &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        rsa_public_key,
    )
    .verify(&crx, &material.signature)
    .map_err(|_| authentication_failed("pinned Widevine signature is invalid"))?;

    Ok(AuthenticatedCrx {
        signed_message: crx,
        archive_offset: prefix_len,
    })
}

struct SignatureMaterial {
    signed_header_data: Vec<u8>,
    signature: Vec<u8>,
}

fn parse_signature_material(header: &[u8], expected_spki: &[u8]) -> Result<SignatureMaterial> {
    let mut fields = ProtobufFields::new(header);
    let mut signed_header_data = None;
    let mut signature = None;

    while let Some(field) = fields.next()? {
        match field.number {
            2 => {
                let proof = field
                    .bytes()
                    .ok_or_else(|| malformed("RSA proof field is not length-delimited"))?;
                if let Some(candidate) = parse_rsa_proof(proof, expected_spki)? {
                    if signature.replace(candidate.to_vec()).is_some() {
                        return Err(malformed("pinned RSA proof appears more than once"));
                    }
                }
            }
            10_000 => {
                let data = field
                    .bytes()
                    .ok_or_else(|| malformed("signed header field is not length-delimited"))?;
                if signed_header_data.replace(data.to_vec()).is_some() {
                    return Err(malformed("signed header field appears more than once"));
                }
            }
            _ => {}
        }
    }

    Ok(SignatureMaterial {
        signed_header_data: signed_header_data
            .ok_or_else(|| malformed("signed header field is missing"))?,
        signature: signature
            .ok_or_else(|| authentication_failed("pinned Widevine proof is missing"))?,
    })
}

fn parse_rsa_proof<'a>(proof: &'a [u8], expected_spki: &[u8]) -> Result<Option<&'a [u8]>> {
    let mut fields = ProtobufFields::new(proof);
    let mut public_key = None;
    let mut signature = None;

    while let Some(field) = fields.next()? {
        match field.number {
            1 => {
                let key = field
                    .bytes()
                    .ok_or_else(|| malformed("RSA public key is not length-delimited"))?;
                if public_key.replace(key).is_some() {
                    return Err(malformed("RSA public key appears more than once"));
                }
            }
            2 => {
                let value = field
                    .bytes()
                    .ok_or_else(|| malformed("RSA signature is not length-delimited"))?;
                if signature.replace(value).is_some() {
                    return Err(malformed("RSA signature appears more than once"));
                }
            }
            _ => {}
        }
    }

    let Some(public_key) = public_key else {
        return Err(malformed("RSA proof has no public key"));
    };
    let Some(signature) = signature else {
        return Err(malformed("RSA proof has no signature"));
    };

    Ok((public_key == expected_spki).then_some(signature))
}

fn parse_signed_data_id(signed_data: &[u8]) -> Result<&[u8]> {
    let mut fields = ProtobufFields::new(signed_data);
    let mut crx_id = None;

    while let Some(field) = fields.next()? {
        if field.number == 1 {
            let value = field
                .bytes()
                .ok_or_else(|| malformed("signed component ID is not length-delimited"))?;
            if crx_id.replace(value).is_some() {
                return Err(malformed("signed component ID appears more than once"));
            }
        }
    }

    let crx_id = crx_id.ok_or_else(|| malformed("signed component ID is missing"))?;
    if crx_id.len() != 16 {
        return Err(malformed("signed component ID is not 16 bytes"));
    }
    Ok(crx_id)
}

struct ProtobufField<'a> {
    number: u32,
    wire_type: u8,
    data: &'a [u8],
}

impl<'a> ProtobufField<'a> {
    fn bytes(&self) -> Option<&'a [u8]> {
        (self.wire_type == 2).then_some(self.data)
    }
}

struct ProtobufFields<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ProtobufFields<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn next(&mut self) -> Result<Option<ProtobufField<'a>>> {
        if self.offset == self.input.len() {
            return Ok(None);
        }

        let key = read_varint(self.input, &mut self.offset)?;
        let number = u32::try_from(key >> 3)
            .ok()
            .filter(|number| (1..=(1 << 29) - 1).contains(number))
            .ok_or_else(|| malformed("protobuf field number is invalid"))?;
        let wire_type = (key & 0x07) as u8;
        let data = match wire_type {
            0 => {
                read_varint(self.input, &mut self.offset)?;
                &self.input[self.offset..self.offset]
            }
            1 => take(self.input, &mut self.offset, 8)?,
            2 => {
                let length = usize::try_from(read_varint(self.input, &mut self.offset)?)
                    .map_err(|_| malformed("protobuf byte-field length overflows usize"))?;
                take(self.input, &mut self.offset, length)?
            }
            5 => take(self.input, &mut self.offset, 4)?,
            _ => return Err(malformed("protobuf wire type is unsupported")),
        };

        Ok(Some(ProtobufField {
            number,
            wire_type,
            data,
        }))
    }
}

fn read_varint(input: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = *input
            .get(*offset)
            .ok_or_else(|| malformed("protobuf varint is truncated"))?;
        *offset += 1;
        if index == 9 && byte > 1 {
            return Err(malformed("protobuf varint overflows u64"));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(malformed("protobuf varint is too long"))
}

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| malformed("protobuf field is truncated"))?;
    let value = &input[*offset..end];
    *offset = end;
    Ok(value)
}

fn rsa_pkcs1_from_spki(spki: &[u8]) -> Result<&[u8]> {
    let mut outer_offset = 0;
    let outer = read_der_value(spki, &mut outer_offset, 0x30)?;
    if outer_offset != spki.len() {
        return Err(malformed("RSA SubjectPublicKeyInfo has trailing bytes"));
    }

    let mut content_offset = 0;
    let algorithm = read_der_value(outer, &mut content_offset, 0x30)?;
    if algorithm != RSA_ENCRYPTION_ALGORITHM {
        return Err(malformed(
            "pinned SubjectPublicKeyInfo is not an RSA encryption key",
        ));
    }
    let bit_string = read_der_value(outer, &mut content_offset, 0x03)?;
    if content_offset != outer.len() || bit_string.first() != Some(&0) {
        return Err(malformed("RSA public-key bit string is invalid"));
    }
    let pkcs1 = &bit_string[1..];

    let mut pkcs1_offset = 0;
    let _ = read_der_value(pkcs1, &mut pkcs1_offset, 0x30)?;
    if pkcs1_offset != pkcs1.len() {
        return Err(malformed("RSA public key has trailing bytes"));
    }
    Ok(pkcs1)
}

fn read_der_value<'a>(input: &'a [u8], offset: &mut usize, tag: u8) -> Result<&'a [u8]> {
    if input.get(*offset) != Some(&tag) {
        return Err(malformed("DER tag is invalid"));
    }
    *offset += 1;
    let first = *input
        .get(*offset)
        .ok_or_else(|| malformed("DER length is missing"))?;
    *offset += 1;

    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let octets = usize::from(first & 0x7f);
        if octets == 0 || octets > std::mem::size_of::<usize>() {
            return Err(malformed("DER length encoding is invalid"));
        }
        let encoded = take(input, offset, octets)?;
        if encoded.first() == Some(&0) {
            return Err(malformed("DER length is not minimally encoded"));
        }
        let mut length = 0_usize;
        for byte in encoded {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| malformed("DER length overflows usize"))?;
        }
        if length < 128 {
            return Err(malformed("DER long-form length is not canonical"));
        }
        length
    };

    take(input, offset, length)
}

fn malformed(message: impl Into<String>) -> Error {
    Error::unknown_bundle_structure(format!(
        "invalid CRX3 signature envelope: {}",
        message.into()
    ))
}

fn authentication_failed(message: impl Into<String>) -> Error {
    Error::hash_mismatch(format!(
        "Widevine CRX3 authentication failed: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    use sha2::{Digest, Sha256};

    use super::{authenticate_crx_with_key, WIDEVINE_COMPONENT_SPKI};

    const TEST_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/crx3-test-key.pk8");
    const TEST_PUBLIC_KEY: &[u8] = include_bytes!("fixtures/crx3-test-key.spki");
    const TEST_ARCHIVE: &[u8] = b"PK\x05\x06test archive covered by the CRX signature";

    #[test]
    fn authenticates_archive_signed_by_pinned_key() {
        let crx = build_signed_crx(None);

        let authenticated = authenticate_crx_with_key(crx, TEST_PUBLIC_KEY)
            .expect("matching key and signature must authenticate");

        assert_eq!(authenticated.archive(), TEST_ARCHIVE);
    }

    #[test]
    fn unsigned_crx3_is_rejected() {
        let mut crx = Vec::new();
        crx.extend_from_slice(b"Cr24");
        crx.extend_from_slice(&3_u32.to_le_bytes());
        crx.extend_from_slice(&0_u32.to_le_bytes());
        crx.extend_from_slice(TEST_ARCHIVE);

        let error = authenticate_crx_with_key(crx, TEST_PUBLIC_KEY)
            .expect_err("an unsigned CRX3 must not become executable input");

        assert_eq!(error.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn archive_tampering_breaks_the_pinned_signature() {
        let mut crx = build_signed_crx(None);
        *crx.last_mut().expect("archive byte") ^= 1;

        let error = authenticate_crx_with_key(crx, TEST_PUBLIC_KEY)
            .expect_err("archive drift must invalidate the signature");

        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn signed_component_id_must_match_the_pinned_key() {
        let crx = build_signed_crx(Some([0_u8; 16]));

        let error = authenticate_crx_with_key(crx, TEST_PUBLIC_KEY)
            .expect_err("a valid signature cannot claim another component ID");

        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn valid_signature_from_an_unpinned_key_is_rejected() {
        let crx = build_signed_crx(None);
        let mut wrong_key = TEST_PUBLIC_KEY.to_vec();
        *wrong_key.last_mut().expect("public key byte") ^= 1;

        let error = authenticate_crx_with_key(crx, &wrong_key)
            .expect_err("self-selected signing keys must not authenticate a CRX");

        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    #[ignore = "requires SILVERVINE_TEST_WIDEVINE_CRX to point at a current vendor CRX3"]
    fn authenticates_current_vendor_crx() {
        let path = std::env::var_os("SILVERVINE_TEST_WIDEVINE_CRX")
            .expect("set SILVERVINE_TEST_WIDEVINE_CRX");
        let crx = std::fs::read(path).expect("read vendor CRX3");

        let authenticated = authenticate_crx_with_key(crx, WIDEVINE_COMPONENT_SPKI)
            .expect("current vendor CRX must carry the pinned developer proof");

        assert!(authenticated.archive().starts_with(b"PK"));
    }

    fn build_signed_crx(crx_id_override: Option<[u8; 16]>) -> Vec<u8> {
        let key_pair = RsaKeyPair::from_pkcs8(TEST_PRIVATE_KEY).expect("test RSA private key");
        let crx_id = crx_id_override.unwrap_or_else(|| {
            Sha256::digest(TEST_PUBLIC_KEY)[..16]
                .try_into()
                .expect("16-byte component ID")
        });

        let mut signed_header_data = Vec::new();
        push_bytes_field(&mut signed_header_data, 1, &crx_id);

        let mut signed_message = Vec::new();
        signed_message.extend_from_slice(super::SIGNATURE_CONTEXT);
        signed_message.extend_from_slice(
            &u32::try_from(signed_header_data.len())
                .expect("small signed header")
                .to_le_bytes(),
        );
        signed_message.extend_from_slice(&signed_header_data);
        signed_message.extend_from_slice(TEST_ARCHIVE);

        let mut signature = vec![0_u8; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                &signed_message,
                &mut signature,
            )
            .expect("sign synthetic CRX");

        let mut proof = Vec::new();
        push_bytes_field(&mut proof, 1, TEST_PUBLIC_KEY);
        push_bytes_field(&mut proof, 2, &signature);

        let mut header = Vec::new();
        push_bytes_field(&mut header, 2, &proof);
        push_bytes_field(&mut header, 10_000, &signed_header_data);

        let mut crx = Vec::new();
        crx.extend_from_slice(b"Cr24");
        crx.extend_from_slice(&3_u32.to_le_bytes());
        crx.extend_from_slice(
            &u32::try_from(header.len())
                .expect("small CRX header")
                .to_le_bytes(),
        );
        crx.extend_from_slice(&header);
        crx.extend_from_slice(TEST_ARCHIVE);
        crx
    }

    fn push_bytes_field(output: &mut Vec<u8>, number: u32, value: &[u8]) {
        push_varint(output, u64::from(number) << 3 | 2);
        push_varint(
            output,
            u64::try_from(value.len()).expect("small test field"),
        );
        output.extend_from_slice(value);
    }

    fn push_varint(output: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            let byte =
                u8::try_from(value & 0x7f).expect("masked protobuf varint chunk must fit in u8");
            output.push(byte | 0x80);
            value >>= 7;
        }
        output.push(u8::try_from(value).expect("final protobuf varint byte must fit in u8"));
    }
}
