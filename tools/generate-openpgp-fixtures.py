#!/usr/bin/env python3
"""Regenerate the checked-in, non-secret OpenPGP verification fixtures."""

from hashlib import sha1, sha256, sha512
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, utils

PRIMARY_PEM = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5j2bUgCR8+ScrUnnMj8ekpi4moGow1ZBc56ysTY/v6cTI/qV
7LGRGd/VCDVM2BwURVn0G4HjHEoMcVWL39D3163E6E8KVqDs+eYnqD+vQqY2wLnR
sggyqIk3YCOYQhn1WXr/043rICvCRhi3FhL9y09YJ2qlLhrB347D6OkMg5GnQY67
qgrS6NEiAS2RVjEZKWi+2TEfsmkXPc+fzguEbhPo9sm8SUpBId2INKRN5qF6w7Th
xlxpk6dLBX8usr3Mn1rJirXNqklcjRhNj1VH1TGMrXex4irRJFz9kGrvyvUWfRoH
zquZUJK9Cf0wyKGgCJa9pywPn6MfavIagwQL3QIDAQABAoIBAAV4wle1DsLqlHSj
1HxDtsDKI1z8ptuZka2jQGDoxqQR3ukUe/qnj6i7Qo9S4PQj2rF5PU1oDVMvSVNq
MoxLpZA5H3xb4IWFhow71YZwmQQu+g8je2HNQxLxS+Ebh3NOtZ9+RlUrQsK9d3z9
+l/qbKCnzpMFPE63sRLUjEBdRYBc6rybKHaXVBH2Na21EPXuPajBIitdrZKVpAUs
PH9CV4UI75ZQnS1Ck7+aUR6lKetkEavOm+JmFz/dQjGd/z+9m8V+9ObFU/rLEK7/
/PiDupGozf2WYcW0/EMtNgdMX0iEwazEX6zGCn2uDNQkNR5uuKRRJfo/KUh17sYO
Pt2NX/sCgYEA/sVHUmZG2IEPZQ95fAujQmnV3Un0d8WxvRThtiRcX2hKcPeJLHzK
qrCAKE2dqjG/wdGCWL24bY0TfWrCYLir4gCpLn6XcjchWJg89PyWIfNdVz92OsLZ
SNnf/n70455A4wF48yc3nZtshn50X8YpC3ZdmIxb11OBhLZr7CRtInsCgYEA51oG
o7zwAHBsFJCa6FZv/d5DGAwECr9l+Uv6tJLIFRlvn2dYUF/PjOFJiC2oHlCJxsXv
2nnPhF/osEkZM0T2TQ7WB5LcZ8HhV4afB0s29QBr+d1idtx2G91vkRsXxS+89n/Q
BEaGGilEX3DRq4Ld+2A1UOzutHSxtvpgY9JYh4cCgYEAk0d8aZgSkIpbWfLOKfWY
VYZVSe2805iHnWT67o6qj8T8c73FoOArUO1jyOjFomPMFMGG9sIGYd5STAhxgfR/
+NCk/OnVpwNT1aF8a6uxJsNHTG61bFbDwaeiI79E1mjf3ds2Dmq3bfcxj7Z+k/c8
NxIgHVXWqe3uS8ghL4wHQw0CgYAeLNvY13fmVsOCGypZS4zn6+mMZWTRkg1W6tYU
X2DBf8PTYsNeGGEV2vygSnQ3IAIYbxDNyj2K4oeTFrW2vjPx8RFxg3JEBkHCDMkJ
RoIwipGK0ZlaL38oO0WmA4aiLYvUCu+y3w/2sZM9b5WpbTRO6UmK+JxZ5S6Y0ydn
XbQ2WQKBgQD9gCv1dlHJWY2OW/BvIwfVXcmPV06EdzDW8ZSAOOmwcwLHIXWP/pnu
OA6kHKDpHnpXQhQLq2iedswCKqubKhlE6XY0GTj+NJdjWaZB2IgiYwPWeoOTH+QL
lbBxJEsTGUyq9q8M3uW7nnexQJQACnKzIVbK18zwKZuKKy1/JkFVqg==
-----END RSA PRIVATE KEY-----
"""

SUBKEY_PEM = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA02dMEtAVhN7D8BN7+XWop9a4oob1YyOfwHZAAxvyKmF38ko/
lfThGDzMSbjpI6tzYgD8gP7/tEcsUiSq6UGe5xGyo50H2hFtW2JsNhBxdvE+ByBW
9KhpW+Rct0gaZQfvyvRGyhwf/lFrnO3x3v6lIEOeB4878PUT5BQwhUm5Eq/D5t0I
PVeCxuvEOX0sj5UzMRrTrTwAfVhg6DiOzVqASC1UuIY51O127q+sQq49i6FLQuxw
Cu/noJYtHtI+oauyDnkLdWyyy4rFLZRSV7mSYe6+DwFH6ibUF0Y6jU7QmJVwvWOd
+usjwlBZr21tu3HffKabHDqReFmymELVETQIPQIDAQABAoIBAAn9CPagl0uyXM6k
lQh52zCm8A1Z1BFNlxg4Xhjngp8nAMxVXsC+k74Z7UsUbguN58M7KbMMmVdSv5DY
A61GuPPQ/cBGRJ80kJavRU6eo0XL6zLZ/9HKfUPmu8y7HugkIlvUA947yvUwsqV1
BqcTIAkwuLBBv8LISZrOq2Y40AJGbrkCBPdkd8I3zhhnFYYwTQGiAlw+bXoXsn7G
7O1Aw2eX8TWX7Euqo4S+kSooaYys/qKAAN+5IBu/SqbbLx+OfwISyppIL0cjq4/R
YaEYpRZn0QmWQai1qVJ1gdxjoIh4w6BMzZG4kDza0PZyCs1slfcbDi1CxTUouGGF
lnaDJ68CgYEA83xyfarTPNbbJfCcStSU7VJukqFneLxB+3MQkSo7F9nOq+0fdNZK
5FlLqFQqptQn1naslFdI8wrPlQCMmFx4g1vGyCEqRZmMrlmCktZxjkWq17AyudTU
IURrF0/9ZQ59PWMkOfLw9EgtXKPdzyObVO4XI2h1fngk9dcwhxDJ6ucCgYEA3kS8
+Cn7GsQ+ECai9wmuCZsgfojkYqxc/h4GPjDZ/XZ8BmDoChpLgGeqNo0I91BgVsmi
QCxbMtleuQKhlaydfu1pVHpZMsJjDw7a8IhTyCroDcXAxPtLqyqWU5IvE1FwMu8R
EBLhGOny4yWFLp0uBPsxPLrCmLtYM37PloouUzsCgYAdqo8Ekri0E/WVlNBmKaqP
k9iXEwVZZ46ehXGCTmPuzwHoXrbTdHyhf+PA+ahMtVK5RbJXTJ89xZZvMCbxNWsV
jiwVHD1bR48lexB2tZwWWpSrPPOhQrYp630k1QEpu+80eIzkZp5HFTg5rlmLMGpv
mabGEKcoJplSPsrR2hDQBwKBgQDNjUQ1PJ28Y0ACL7kGPS12NMAYRQDxP/XADIQ5
f3QZszl/rJ7quOaaGUSQrl1cWji+CjrCnkK5A81Vy9kjUj9U4rpGJd/X0W1Kv7I6
P9k7hHKWSgu8H6oa4YekQczHUMkyUWS2OL9zCuhUqJ5CPZoRgTxHrW/JT3iCJwRT
c/bjgQKBgQDyMGSCLDTrqW/HHv+6QhV92i0vCEVG7O7MhQGlFTKFQGkp2OEXS+KJ
uMEf1hn68KTvVN09knWBaIhtkRx2OCoHZxu3ig78Tr/uuYZZeSty/11+OsrvlrYA
R6HZAnW1Jd8UUZg229znRGB/PZiWUl7ttI8x4zY1oz5uzaSQfYGRRQ==
-----END RSA PRIVATE KEY-----
"""

CREATED = 1_700_000_000
MESSAGE = b"Origin: debz fixture\nSuite: stable\n"
UID = b"debz hermetic archive fixture <fixture.invalid>"


def mpi(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return value.bit_length().to_bytes(2, "big") + raw


def packet(tag, body):
    size = len(body)
    if size < 192:
        length = bytes([size])
    elif size < 8384:
        adjusted = size - 192
        length = bytes([(adjusted >> 8) + 192, adjusted & 255])
    else:
        length = b"\xff" + size.to_bytes(4, "big")
    return bytes([0xC0 | tag]) + length + body


def packet_body(encoded):
    first = encoded[1]
    if first < 192:
        return encoded[2:]
    if first <= 223:
        return encoded[3:]
    if first == 255:
        return encoded[6:]
    raise ValueError("partial packet")


def public_body(key):
    if isinstance(key, ed25519.Ed25519PrivateKey):
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        oid = bytes.fromhex("2b06010401da470f01")
        return (
            b"\x04" + CREATED.to_bytes(4, "big") + b"\x16"
            + bytes([len(oid)]) + oid + mpi(int.from_bytes(b"\x40" + raw, "big"))
        )
    numbers = key.public_key().public_numbers()
    return b"\x04" + CREATED.to_bytes(4, "big") + b"\x01" + mpi(numbers.n) + mpi(numbers.e)


def fingerprint(body):
    return sha1(b"\x99" + len(body).to_bytes(2, "big") + body).digest()


def subpacket(kind, data, critical=False):
    body = bytes([kind | (0x80 if critical else 0)]) + data
    size = len(body)
    if size < 192:
        length = bytes([size])
    elif size < 8384:
        adjusted = size - 192
        length = bytes([(adjusted >> 8) + 192, adjusted & 255])
    else:
        length = b"\xff" + size.to_bytes(4, "big")
    return length + body


def signature(key, sig_type, signed_parts, signer_fp, hash_id=8, extra_hashed=b"", created=CREATED):
    hashed = (
        subpacket(2, created.to_bytes(4, "big"))
        + subpacket(33, b"\x04" + signer_fp)
        + extra_hashed
    )
    public_key_algorithm = 22 if isinstance(key, ed25519.Ed25519PrivateKey) else 1
    prefix = bytes([4, sig_type, public_key_algorithm, hash_id]) + len(hashed).to_bytes(2, "big") + hashed
    trailer = b"\x04\xff" + len(prefix).to_bytes(4, "big")
    digest_fn = sha256 if hash_id == 8 else sha512
    digest = digest_fn(b"".join(signed_parts) + prefix + trailer).digest()
    algorithm = hashes.SHA256() if hash_id == 8 else hashes.SHA512()
    if public_key_algorithm == 22:
        raw_sig = key.sign(digest)
        encoded_sig = mpi(int.from_bytes(raw_sig[:32], "big")) + mpi(int.from_bytes(raw_sig[32:], "big"))
    else:
        raw_sig = key.sign(digest, padding.PKCS1v15(), utils.Prehashed(algorithm))
        encoded_sig = mpi(int.from_bytes(raw_sig, "big"))
    unhashed = subpacket(16, signer_fp[-8:])
    body = prefix + len(unhashed).to_bytes(2, "big") + unhashed + digest[:2] + encoded_sig
    return packet(2, body)


def key_prefix(body):
    return b"\x99" + len(body).to_bytes(2, "big") + body


def emit_array(name, data):
    lines = [f"pub const {name} = [_]u8{{"]
    for offset in range(0, len(data), 16):
        chunk = ", ".join(f"0x{byte:02x}" for byte in data[offset:offset + 16])
        lines.append(f"    {chunk},")
    lines.append("};")
    return "\n".join(lines)


def main():
    primary = serialization.load_pem_private_key(PRIMARY_PEM, password=None)
    subkey = serialization.load_pem_private_key(SUBKEY_PEM, password=None)
    ed_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    primary_body = public_body(primary)
    subkey_body = public_body(subkey)
    primary_fp = fingerprint(primary_body)
    subkey_fp = fingerprint(subkey_body)

    primary_packet = packet(6, primary_body)
    uid_packet = packet(13, UID)
    certification = signature(
        primary, 0x13,
        [key_prefix(primary_body), b"\xb4" + len(UID).to_bytes(4, "big") + UID],
        primary_fp,
        extra_hashed=subpacket(27, b"\x01"),
    )
    subkey_packet = packet(14, subkey_body)
    binding_parts = [key_prefix(primary_body), key_prefix(subkey_body)]
    primary_binding = signature(subkey, 0x19, binding_parts, subkey_fp)
    signing_binding_subpackets = (
        subpacket(27, b"\x02") + subpacket(32, packet_body(primary_binding))
    )
    binding = signature(
        primary, 0x18, binding_parts, primary_fp,
        extra_hashed=signing_binding_subpackets,
    )
    expiring_binding = signature(
        primary, 0x18, binding_parts, primary_fp,
        extra_hashed=subpacket(9, (60).to_bytes(4, "big")) + signing_binding_subpackets,
    )
    authorization_expiring_binding = signature(
        primary, 0x18, binding_parts, primary_fp,
        extra_hashed=subpacket(3, (60).to_bytes(4, "big")) + signing_binding_subpackets,
    )
    non_signing_binding = signature(
        primary, 0x18, binding_parts, primary_fp,
        extra_hashed=subpacket(27, b"\x04"),
    )
    uncertified_binding = signature(primary, 0x18, binding_parts, primary_fp)
    late_binding = signature(
        primary, 0x18, binding_parts, primary_fp,
        extra_hashed=signing_binding_subpackets,
        created=CREATED + 20,
    )
    revocation = signature(primary, 0x28, binding_parts, primary_fp)

    document_signature = signature(subkey, 0x00, [MESSAGE], subkey_fp)
    canonical_message = MESSAGE.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    text_signature = signature(subkey, 0x01, [canonical_message], subkey_fp)
    sha512_signature = signature(subkey, 0x00, [MESSAGE], subkey_fp, hash_id=10)
    expiring_signature = signature(
        subkey, 0x00, [MESSAGE], subkey_fp,
        extra_hashed=subpacket(3, (60).to_bytes(4, "big")),
    )
    unknown_critical_signature = signature(
        subkey, 0x00, [MESSAGE], subkey_fp,
        extra_hashed=subpacket(100, b"\x01", critical=True),
    )
    ed_body = public_body(ed_key)
    ed_fp = fingerprint(ed_body)
    ed_packet = packet(6, ed_body)
    ed_certification = signature(
        ed_key, 0x13,
        [key_prefix(ed_body), b"\xb4" + len(UID).to_bytes(4, "big") + UID],
        ed_fp,
        extra_hashed=subpacket(27, b"\x03"),
    )
    ed_keyring = ed_packet + uid_packet + ed_certification
    ed_signature = signature(ed_key, 0x00, [MESSAGE], ed_fp)

    values = {
        "message": MESSAGE,
        "keyring": primary_packet + uid_packet + certification + subkey_packet + binding,
        "expired_keyring": primary_packet + uid_packet + certification + subkey_packet + expiring_binding,
        "authorization_expired_keyring": primary_packet + uid_packet + certification + subkey_packet + authorization_expiring_binding,
        "non_signing_keyring": primary_packet + uid_packet + certification + subkey_packet + non_signing_binding,
        "uncertified_keyring": primary_packet + uid_packet + certification + subkey_packet + uncertified_binding,
        "late_binding_keyring": primary_packet + uid_packet + certification + subkey_packet + late_binding,
        "revoked_keyring": primary_packet + uid_packet + certification + subkey_packet + binding + revocation,
        "signature": document_signature,
        "text_signature": text_signature,
        "sha512_signature": sha512_signature,
        "expired_signature": expiring_signature,
        "unknown_critical_signature": unknown_critical_signature,
        "ed25519_keyring": ed_keyring,
        "ed25519_signature": ed_signature,
        "primary_fingerprint": primary_fp,
        "subkey_fingerprint": subkey_fp,
        "ed25519_fingerprint": ed_fp,
    }
    header = (
        "// Generated by tools/generate-openpgp-fixtures.py. The private keys are test-only.\n"
        f"pub const created: i64 = {CREATED};\n"
    )
    output = header + "\n\n".join(emit_array(name, value) for name, value in values.items()) + "\n"
    Path("src/fixtures/openpgp.zig").write_text(output)


if __name__ == "__main__":
    main()
