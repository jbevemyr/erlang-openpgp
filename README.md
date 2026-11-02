## erlang-openpgp (Erlang) – without `gpg`

Pure Erlang code to **decode** and **encode** OpenPGP/GPG key material in “gpg format”:

- **ASCII Armor** (`-----BEGIN PGP ...-----`) including Base64 and CRC24
- **OpenPGP packets** (RFC 4880) – parse/serialize packet framing (tag + length + body)

This repo focuses on OpenPGP formats and interoperability, and includes key import/export and basic signing/verification helpers (RSA + Ed25519).

### Examples

Decode an armored public key (or secret key) into packets:

```erlang
{ok, #{armor := Armor, packets := Packets}} = gpg_keys:decode(PubArmoredBinOrString).
```

Encode packets back into an armored public key:

```erlang
Armored = gpg_keys:encode_public(Packets).
```

If you already have raw packet binary data (without ASCII armor):

```erlang
Armored2 = gpg_keys:encode_public(RawPacketsBinary).
```

### OpenPGP ↔ crypto format (OTP)

The `openpgp_crypto` module converts between OpenPGP key blocks and formats understood by OTP `crypto`.

Import a public key from GPG/OpenPGP into crypto format:

```erlang
{ok, {rsa, [E, N]}} = openpgp_crypto:import_public(ArmoredOrBinary).
{ok, {ed25519, Pub32}} = openpgp_crypto:import_public(ArmoredOrBinary).
```

Import an (unencrypted) secret key if present, from a public or a secret keyblock:

```erlang
{ok, #{public := Pub, secret := SecretOrUndefined}} = openpgp_crypto:import_keypair(ArmoredOrBinary).
```

Export a public key from crypto format to OpenPGP (GPG format). For best compatibility, provide a signing key for a self-certification signature:

```erlang
{PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
{ok, Armored, _Fpr} =
    openpgp_crypto:export_public({rsa, PubRsa}, #{
        userid => <<"Me <me@example.com>">>,
        signing_key => PrivRsa,
        % Optional primary key usage (Key Flags subpacket 27):
        primary_key_flags => [certify, sign],
        % Optional primary key expiration in seconds:
        primary_expires => 3600
    }).
```

```erlang
{PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
{ok, Armored, _Fpr} =
    openpgp_crypto:export_public({ed25519, PubEd}, #{
        userid => <<"Me <me@example.com>">>,
        signing_key => PrivEd
    }).
```

### Primary + subkey (export a keyblock suitable for verifying subkey signatures in `gpg`)

If you want to verify signatures made with a **signing subkey** in `gpg`, you typically need a keyblock that contains:

- a **primary key** (tag 6) + User ID + self-cert
- a **public subkey** (tag 14)
- a **subkey binding signature** (0x18) that includes an embedded **primary key binding signature** (0x19, “cross-cert”)

This repo provides a helper that exports such a keyblock:

```erlang
Data = <<"The brown fox">>,

{PrimaryPub, PrimaryPriv} = crypto:generate_key(eddsa, ed25519),
{SubPub, SubPriv} = crypto:generate_key(eddsa, ed25519),

{ok, PubKeyBlock, #{primary_fpr := _PrimaryFpr, subkey_fpr := SubFpr}} =
    openpgp_crypto:export_public_with_subkey(
        {ed25519, PrimaryPub},
        {ed25519, SubPub},
        #{
            userid => <<"Me <me@example.com>">>,
            signing_key => PrimaryPriv,
            subkey_signing_key => SubPriv,
            subkey_flags => [sign], % or 16#02
            subkey_expires => 86400
        }
    ),

% Sign using the subkey (no special signing API is needed):
{ok, SigArmored} = openpgp_detached_sig:sign(Data, {ed25519, SubPriv}, #{hash => sha512, issuer_fpr => SubFpr}).
```

Import such a keyblock and extract the subkey public key for verification:

```erlang
{ok, Bundle} = openpgp_crypto:import_public_bundle(PubKeyBlock),
Subkeys = maps:get(subkeys, Bundle),
[#{pub := {ed25519, SubPub32}}] = [S || S <- Subkeys, maps:get(fpr, S) =:= SubFpr],
ok = openpgp_detached_sig:verify(Data, SigArmored, {ed25519, SubPub32}).
```

The import checks the signatures that hold the keyblock together, as GnuPG
does: a revoked or expired primary key is an error, `userids` holds only User
IDs with a valid self-certification that has not been revoked (the primary
one first), and `subkeys` only subkeys with a valid binding (and back
signature, for signing subkeys) that are neither revoked nor expired. The
other subkeys are listed in `rejected_subkeys` with the reason. Signatures
by other keys, and signatures that do not verify, are ignored.

If you know the subkey **keyid**, you can look up the subkey public key directly:

```erlang
{ok, Bundle} = openpgp_crypto:import_public_bundle(PubKeyBlock),
{ok, SubPub} = openpgp_crypto:subkey_pub_by_keyid(Bundle, SubKeyId),
ok = openpgp_detached_sig:verify(Data, SigArmored, SubPub).
```

### Export from `public_key` record formats

If you have keys as ASN.1 records (e.g. `#'RSAPublicKey'{...}` or Ed25519 from `public_key:generate_key/1`),
you can export directly using `openpgp_crypto:export_public_key/2`:

```erlang
{ok, Armored, _Fpr} =
    openpgp_crypto:export_public_key(RsaPubRec, #{userid => <<"Me <me@example.com>">>}).
```

For Ed25519 from:

```erlang
Spec = {namedCurve, pubkey_cert_records:namedCurves(ed25519)},
{PubRec, PrivRec} = public_key:generate_key(Spec).
```

…you can export either from the public record, or from the private record (if it contains the privateKey we can self-sign):

```erlang
{ok, Armored, _Fpr} =
    openpgp_crypto:export_public_key(PubRec, #{userid => <<"Me <me@example.com>">>}).
```

### Export secret keys (PGP PRIVATE KEY BLOCK)

Exporting **secret keys** is supported, but currently only **unencrypted** secret keys are exported
(S2K usage = `0`). Treat the output as sensitive.

From OTP `crypto` format:

```erlang
{_PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
{ok, ArmoredSec, _Fpr} =
    openpgp_crypto:export_secret({rsa, PrivRsa}, #{userid => <<"Me <me@example.com>">>, signing_key => PrivRsa}).
```

```erlang
{PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
{ok, ArmoredSec, _Fpr} =
    openpgp_crypto:export_secret({ed25519, {PubEd, PrivEd}}, #{userid => <<"Me <me@example.com>">>, signing_key => PrivEd}).
```

From `public_key` record formats:

```erlang
{ok, ArmoredSec, _Fpr} =
    openpgp_crypto:export_secret_key(RsaPrivRec, #{userid => <<"Me <me@example.com>">>}).
```

### Sign and verify (detached signatures)

This repo supports **detached signatures** (OpenPGP v4 Signature packet, sigtype `0x00` = “binary document”).

Create a signature in Erlang and verify with `gpg`:

```erlang
Data = <<"The brown fox">>,
{PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
{ok, PubArmored, Fpr} =
    openpgp_crypto:export_public({rsa, PubRsa}, #{userid => <<"Me <me@example.com>">>, signing_key => PrivRsa}),
{ok, SigArmored} =
    openpgp_detached_sig:sign(Data, {rsa, PrivRsa}, #{hash => sha512, issuer_fpr => Fpr}).
```

Verify a `gpg`-created detached signature in Erlang:

```erlang
ok = openpgp_detached_sig:verify(Data, SigArmoredOrBinary, {rsa, [E, N]}).
ok = openpgp_detached_sig:verify(Data, SigArmoredOrBinary, {ed25519, Pub32}).
```

Besides the signature itself, verification requires a creation time, rejects
signatures that are expired or carry an unknown critical subpacket, and
accepts SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256 and SHA3-512. Options
in `verify/4` add checks: `sig_type`, `issuer_fpr`, `key_created`,
`key_expires` and `now`. A signature block with signatures by several keys
verifies when one of them does.

Create a **binary** detached signature (no ASCII armor):

```erlang
{ok, SigBin} =
    openpgp_detached_sig:sign(Data, {ed25519, PrivEd}, #{hash => sha256, armor => false}).
```

### Cleartext signatures (clearsign)

Create a clearsigned text (`-----BEGIN PGP SIGNED MESSAGE-----`) in Erlang and verify with `gpg`:

```erlang
Text = <<"The brown fox\n">>,
{PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
{ok, PubArmored, Fpr} =
    openpgp_crypto:export_public({ed25519, PubEd}, #{userid => <<"Me <me@example.com>">>, signing_key => PrivEd}),
{ok, ClearSigned} =
    openpgp_cleartext:sign(Text, {ed25519, PrivEd}, #{hash => sha512, issuer_fpr => Fpr}).
```

Verify a clearsigned message in Erlang:

```erlang
ok = openpgp_cleartext:verify(ClearSignedBin, {ed25519, Pub32}).
ok = openpgp_cleartext:verify(ClearSignedBin, {rsa, [E, N]}).
```



