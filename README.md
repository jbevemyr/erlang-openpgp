## gpg_keys (Erlang) – utan `gpg`

Ren Erlang-kod för att **avkoda** och **koda** OpenPGP/GPG-nyckelblock i “gpg-format”:

- **ASCII Armor** (`-----BEGIN PGP ...-----`) inkl. Base64 och CRC24
- **OpenPGP packets** (RFC 4880) – vi parsar/serialiserar packet-ramning (tag + längd + body)

Detta hanterar alltså formatet, men **hanterar inte** keyring, signaturvalidering eller kryptografiska operationer.

### Exempel

Avkoda en armorerad publik nyckel (eller privat) till packets:

```erlang
{ok, #{armor := Armor, packets := Packets}} = gpg_keys:decode(PubArmoredBinOrString).
```

Koda packets tillbaka till en armorerad publik nyckel:

```erlang
Armored = gpg_keys:encode_public(Packets).
```

Om du redan har rå packet-binära data (utan ASCII armor):

```erlang
Armored2 = gpg_keys:encode_public(RawPacketsBinary).
```

### OpenPGP ↔ crypto-format (OTP)

Modulen `openpgp_crypto` kan konvertera mellan OpenPGP-nyckelblock och format som OTP:s `crypto` förstår.

Importera publik nyckel från GPG/OpenPGP till crypto-format:

```erlang
{ok, {rsa, [E, N]}} = openpgp_crypto:import_public(ArmoredOrBinary).
{ok, {ed25519, Pub32}} = openpgp_crypto:import_public(ArmoredOrBinary).
```

Importera (unencrypted) secret key om den finns:

```erlang
{ok, #{public := Pub, secret := SecretOrUndefined}} = openpgp_crypto:import_keypair(ArmoredOrBinary).
```

Exportera publik nyckel från crypto-format till OpenPGP (GPG-format). För bäst kompatibilitet kan du ge med en signing key för self-cert:

```erlang
{PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
{ok, Armored, _Fpr} =
    openpgp_crypto:export_public({rsa, PubRsa}, #{
        userid => <<"Me <me@example.com>">>,
        signing_key => PrivRsa
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

### Export från `public_key`-record-format

Om du har nycklar som ASN.1-records (t.ex. `#'RSAPublicKey'{...}` eller Ed25519 från `public_key:generate_key/1`)
kan du exportera direkt med `openpgp_crypto:export_public_key/2`:

```erlang
{ok, Armored, _Fpr} =
    openpgp_crypto:export_public_key(RsaPubRec, #{userid => <<"Me <me@example.com>">>}).
```

För Ed25519 från:

```erlang
Spec = {namedCurve, pubkey_cert_records:namedCurves(ed25519)},
{PubRec, PrivRec} = public_key:generate_key(Spec).
```

…kan du exportera antingen från publika recordet eller från privata (om den innehåller privateKey kan vi self-signa):

```erlang
{ok, Armored, _Fpr} =
    openpgp_crypto:export_public_key(PubRec, #{userid => <<"Me <me@example.com>">>}).
```

### Export av privat nyckel (PGP PRIVATE KEY BLOCK)

Det går att exportera **privata nycklar** också – men just nu exporterar vi endast **okrypterade** secret keys
(S2K usage = `0`). Hantera output som hemlig information.

Från OTP `crypto`-format:

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

Från `public_key`-record-format:

```erlang
{ok, ArmoredSec, _Fpr} =
    openpgp_crypto:export_secret_key(RsaPrivRec, #{userid => <<"Me <me@example.com>">>}).
```

### Signera och verifiera (detached signatures)

Detta repo stöder **detached signatures** (OpenPGP Signature packet v4, sigtype `0x00` = “binary document”).

Skapa en signatur i Erlang och verifiera med `gpg`:

```erlang
Data = <<"The brown fox">>,
{PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
{ok, PubArmored, Fpr} =
    openpgp_crypto:export_public({rsa, PubRsa}, #{userid => <<"Me <me@example.com>">>, signing_key => PrivRsa}),
{ok, SigArmored} =
    openpgp_detached_sig:sign(Data, {rsa, PrivRsa}, #{hash => sha512, issuer_fpr => Fpr}).
```

Verifiera en `gpg`-skapad detached signatur i Erlang:

```erlang
ok = openpgp_detached_sig:verify(Data, SigArmoredOrBinary, {rsa, [E, N]}).
ok = openpgp_detached_sig:verify(Data, SigArmoredOrBinary, {ed25519, Pub32}).
```

### Cleartext signatures (clearsign)

Skapa en clearsigned text (`-----BEGIN PGP SIGNED MESSAGE-----`) i Erlang och verifiera med `gpg`:

```erlang
Text = <<"The brown fox\n">>,
{PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
{ok, PubArmored, Fpr} =
    openpgp_crypto:export_public({ed25519, PubEd}, #{userid => <<"Me <me@example.com>">>, signing_key => PrivEd}),
{ok, ClearSigned} =
    openpgp_cleartext:sign(Text, {ed25519, PrivEd}, #{hash => sha512, issuer_fpr => Fpr}).
```

Verifiera en clearsigned message i Erlang:

```erlang
ok = openpgp_cleartext:verify(ClearSignedBin, {ed25519, Pub32}).
ok = openpgp_cleartext:verify(ClearSignedBin, {rsa, [E, N]}).
```



