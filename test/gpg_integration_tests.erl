%%% Integration tests against gpg.
%%%
%%% These tests require `gpg` installed and available in PATH.
%%% They generate keys inside isolated GNUPGHOME directories under /tmp.
-module(gpg_integration_tests).

-include_lib("eunit/include/eunit.hrl").

gpg_required_test_() ->
    case os:find_executable("gpg") of
        false ->
            [];
        _ ->
            case should_run_gpg_tests() of
                {skip, Reason} ->
                    % EUnit (at least in some OTP versions) doesn't accept {skip,Reason} as a test descriptor.
                    % Return a single "note" test so the reason is visible in verbose output.
                    [{"SKIP gpg integration tests: " ++ Reason, fun() -> ok end}];
                ok ->
                    case gpg_preflight() of
                        ok ->
                            gpg_tests();
                        {skip, Reason} ->
                            [{"SKIP gpg integration tests (preflight): " ++ skip_reason_to_list(Reason), fun() -> ok end}]
                    end
            end
    end.

skip_reason_to_list(Bin) when is_binary(Bin) -> binary_to_list(Bin);
skip_reason_to_list(List) when is_list(List) -> List;
skip_reason_to_list(Other) -> lists:flatten(io_lib:format("~p", [Other])).

gpg_tests() ->
    [
        {"gpg -> Erlang decode/encode -> gpg import (RSA)", fun rsa_roundtrip/0},
        {"gpg -> Erlang decode/encode -> gpg import (Ed25519)", fun ed25519_roundtrip/0},
        {"Erlang -> gpg import (RSA, public+secret)", fun erlang_rsa_to_gpg_import/0},
        {"Erlang -> gpg import (Ed25519, public+secret)", fun erlang_ed25519_to_gpg_import/0},
        {"gpg -> crypto-format (RSA/Ed25519)", fun gpg_to_crypto_public/0},
        {"crypto-format -> gpg import (public, RSA/Ed25519)", fun crypto_to_gpg_public/0},
        {"sign in Erlang and verify with gpg (RSA/Ed25519)", fun erlang_sign_gpg_verify/0},
        {"sign in Erlang with subkey and verify with gpg (Ed25519 primary + Ed25519 subkey)", fun erlang_sign_subkey_gpg_verify/0},
        {"import primary+subkey bundle and verify subkey signature in Erlang", fun import_bundle_verify_subkey_sig/0},
        {"gpg generates key+signing-subkey, signs, export public, import in Erlang, verify with subkey", fun gpg_signing_subkey_erlang_verify/0},
        {"sign in gpg and verify in Erlang (RSA/Ed25519)", fun gpg_sign_erlang_verify/0},
        {"clearsign in Erlang and verify with gpg (RSA/Ed25519)", fun erlang_clearsign_gpg_verify/0},
        {"clearsign in gpg and verify in Erlang (RSA/Ed25519)", fun gpg_clearsign_erlang_verify/0},
        {"export secret key from crypto-format and import into gpg (RSA/Ed25519)", fun crypto_to_gpg_secret/0}
    ].

should_run_gpg_tests() ->
    % Default: run locally. In CI: require explicit opt-in, because many runners
    % have broken/locked-down gpg-agent/keyboxd setups.
    case os:getenv("RUN_GPG_TESTS") of
        "1" ->
            ok;
        "true" ->
            ok;
        _ ->
            case os:getenv("CI") of
                false -> ok;
                "" -> ok;
                _ -> {skip, "CI environment: set RUN_GPG_TESTS=1 to run gpg integration tests"}
            end
    end.

gpg_preflight() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),
        % This triggers keybox initialization; if CI environment blocks gpg/keyboxd, we skip.
        case gpg(Home, ["--batch", "--yes", "--list-keys"]) of
            {ok, _} ->
                ok;
            {error, {gpg_failed, Status, Out}} ->
                {skip, iolist_to_binary([<<"gpg preflight failed (">>, integer_to_binary(Status), <<"): ">>, Out])};
            {error, timeout} ->
                {skip, <<"gpg preflight timeout">>};
            {error, Other} ->
                {skip, io_lib:format("gpg preflight error: ~p", [Other])}
        end
    after
        Cleanup()
    end.

rsa_roundtrip() ->
    roundtrip_key(rsa).

ed25519_roundtrip() ->
    roundtrip_key(ed25519).

erlang_rsa_to_gpg_import() ->
    erlang_to_gpg_import(rsa).

erlang_ed25519_to_gpg_import() ->
    erlang_to_gpg_import(ed25519).

gpg_to_crypto_public() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        ok = gen_key(Home, rsa, "gpg2crypto-rsa@example.com"),
        {ok, PubRsa} = gpg_export_public(Home, "gpg2crypto-rsa@example.com"),
        {ok, {rsa, [E, N]}} = openpgp_crypto:import_public(PubRsa),
        ?assert(is_binary(E)),
        ?assert(is_binary(N)),

        ok = gen_key(Home, ed25519, "gpg2crypto-ed@example.com"),
        {ok, PubEd} = gpg_export_public(Home, "gpg2crypto-ed@example.com"),
        {ok, {ed25519, Pub32}} = openpgp_crypto:import_public(PubEd),
        ?assertEqual(32, byte_size(Pub32))
    after
        Cleanup()
    end.

crypto_to_gpg_public() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        {PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
        EmailRsa = "crypto-rsa@example.com",
        {ok, ArmoredRsa, FprRsa} =
            openpgp_crypto:export_public({rsa, PubRsa}, #{
                userid => <<"Crypto RSA <crypto-rsa@example.com>">>,
                signing_key => PrivRsa
            }),
        ok = gpg_import_public(Home, ArmoredRsa),
        {ok, FprGpg1} = gpg_fingerprint(Home, EmailRsa),
        ?assertEqual(hex_lower(FprRsa), string:lowercase(binary_to_list(FprGpg1))),

        {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
        EmailEd = "crypto-ed@example.com",
        {ok, ArmoredEd, FprEd} =
            openpgp_crypto:export_public({ed25519, PubEd}, #{
                userid => <<"Crypto Ed25519 <crypto-ed@example.com>">>,
                signing_key => PrivEd
            }),
        ok = gpg_import_public(Home, ArmoredEd),
        {ok, FprGpg2} = gpg_fingerprint(Home, EmailEd),
        ?assertEqual(hex_lower(FprEd), string:lowercase(binary_to_list(FprGpg2)))
    after
        Cleanup()
    end.

erlang_sign_gpg_verify() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        Data = <<"The brown fox">>,
        DataPath = filename:join(Tmp, "msg.txt"),
        ok = file:write_file(DataPath, Data),

        % RSA
        {PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
        {ok, PubArmoredRsa, FprRsa} =
            openpgp_crypto:export_public({rsa, PubRsa}, #{
                userid => <<"Signer RSA <signer-rsa@example.com>">>,
                signing_key => PrivRsa
            }),
        ok = gpg_import_public(Home, PubArmoredRsa),
        {ok, SigRsa} = openpgp_detached_sig:sign(Data, {rsa, PrivRsa}, #{hash => sha512, issuer_fpr => FprRsa}),
        SigRsaPath = filename:join(Tmp, "sig-rsa.asc"),
        ok = file:write_file(SigRsaPath, SigRsa),
        ok = gpg_verify_detached(Home, SigRsaPath, DataPath),

        % Ed25519
        {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
        {ok, PubArmoredEd, FprEd} =
            openpgp_crypto:export_public({ed25519, PubEd}, #{
                userid => <<"Signer Ed25519 <signer-ed@example.com>">>,
                signing_key => PrivEd
            }),
        ok = gpg_import_public(Home, PubArmoredEd),
        {ok, SigEd} = openpgp_detached_sig:sign(Data, {ed25519, PrivEd}, #{hash => sha512, issuer_fpr => FprEd}),
        SigEdPath = filename:join(Tmp, "sig-ed.asc"),
        ok = file:write_file(SigEdPath, SigEd),
        ok = gpg_verify_detached(Home, SigEdPath, DataPath)
    after
        Cleanup()
    end.

erlang_sign_subkey_gpg_verify() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        Data = <<"The brown fox">>,
        DataPath = filename:join(Tmp, "msg.txt"),
        ok = file:write_file(DataPath, Data),

        {PrimaryPub, PrimaryPriv} = crypto:generate_key(eddsa, ed25519),
        {SubPub, SubPriv} = crypto:generate_key(eddsa, ed25519),

        % Use deterministic timestamps so fingerprints are stable.
        Created = 1700000000,
        {ok, PubArmored, #{primary_fpr := _PrimaryFpr, subkey_fpr := SubFpr}} =
            openpgp_crypto:export_public_with_subkey(
                {ed25519, PrimaryPub},
                {ed25519, SubPub},
                #{
                    userid => <<"Signer (subkey) <signer-subkey@example.com>">>,
                    created => Created,
                    subkey_created => Created + 1,
                    signing_key => PrimaryPriv,
                    subkey_signing_key => SubPriv,
                    % "This key may be used to sign data"
                    subkey_flags => [sign]
                }
            ),
        ok = gpg_import_public(Home, PubArmored),

        {ok, Sig} = openpgp_detached_sig:sign(Data, {ed25519, SubPriv}, #{hash => sha512, issuer_fpr => SubFpr}),
        SigPath = filename:join(Tmp, "sig-subkey.asc"),
        ok = file:write_file(SigPath, Sig),
        ok = gpg_verify_detached(Home, SigPath, DataPath)
    after
        Cleanup()
    end.

import_bundle_verify_subkey_sig() ->
    % Build a primary+subkey keyblock, import it structurally, then verify a signature made with the subkey.
    Data = <<"The brown fox">>,
    {PrimaryPub, PrimaryPriv} = crypto:generate_key(eddsa, ed25519),
    {SubPub, SubPriv} = crypto:generate_key(eddsa, ed25519),

    Created = 1700000000,
    {ok, PubKeyBlock, #{subkey_fpr := SubFpr}} =
        openpgp_crypto:export_public_with_subkey(
            {ed25519, PrimaryPub},
            {ed25519, SubPub},
            #{
                userid => <<"Bundle <bundle@example.com>">>,
                created => Created,
                subkey_created => Created + 1,
                signing_key => PrimaryPriv,
                subkey_signing_key => SubPriv,
                subkey_flags => 16#02
            }
        ),

    {ok, Bundle} = openpgp_crypto:import_public_bundle(PubKeyBlock),
    Subkeys = maps:get(subkeys, Bundle),
    % Find the subkey by fingerprint:
    [#{pub := {ed25519, SubPub32}}] = [S || S <- Subkeys, maps:get(fpr, S) =:= SubFpr],

    {ok, Sig} = openpgp_detached_sig:sign(Data, {ed25519, SubPriv}, #{hash => sha512, issuer_fpr => SubFpr}),
    ok = openpgp_detached_sig:verify(Data, Sig, {ed25519, SubPub32}).

gpg_signing_subkey_erlang_verify() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        Data = <<"The brown fox">>,
        DataPath = filename:join(Tmp, "msg.txt"),
        ok = file:write_file(DataPath, Data),

        % RSA: create primary cert-only + signing subkey, sign as subkey, verify in Erlang using imported subkey pub.
        EmailRsa = "gpgsub-rsa@example.com",
        ok = gen_key_signing_subkey(Home, rsa, EmailRsa),
        {ok, PubRsaArmored} = gpg_export_public(Home, EmailRsa),
        {ok, BundleRsa} = openpgp_crypto:import_public_bundle(PubRsaArmored),
        SubKeyIdRsa = binary_to_list(gpg_first_secret_subkey_keyid(Home, EmailRsa)),
        SigRsaPath = filename:join(Tmp, "gpg-sub-rsa.sig"),
        ok = gpg_sign_detached(Home, SubKeyIdRsa, DataPath, SigRsaPath),
        {ok, SigRsa} = file:read_file(SigRsaPath),
        PrimaryRsa = maps:get(primary, BundleRsa),
        % Primary should NOT verify (we signed with the subkey)
        ?assertMatch({error, _}, openpgp_detached_sig:verify(Data, SigRsa, PrimaryRsa)),
        {ok, SubPubRsa} = pick_signing_subkey_pub(BundleRsa),
        ok = openpgp_detached_sig:verify(Data, SigRsa, SubPubRsa),

        % Ed25519: same flow (skip if environment can't generate Ed25519 subkeys in batch).
        EmailEd = "gpgsub-ed@example.com",
        case gen_key_signing_subkey(Home, ed25519, EmailEd) of
            ok ->
                {ok, PubEdArmored} = gpg_export_public(Home, EmailEd),
                {ok, BundleEd} = openpgp_crypto:import_public_bundle(PubEdArmored),
                SubKeyIdEd = binary_to_list(gpg_first_secret_subkey_keyid(Home, EmailEd)),
                SigEdPath = filename:join(Tmp, "gpg-sub-ed.sig"),
                ok = gpg_sign_detached(Home, SubKeyIdEd, DataPath, SigEdPath),
                {ok, SigEd} = file:read_file(SigEdPath),
                PrimaryEd = maps:get(primary, BundleEd),
                ?assertMatch({error, _}, openpgp_detached_sig:verify(Data, SigEd, PrimaryEd)),
                {ok, SubPubEd} = pick_signing_subkey_pub(BundleEd),
                ok = openpgp_detached_sig:verify(Data, SigEd, SubPubEd);
            {skip, _Reason} ->
                ok
        end
    after
        Cleanup()
    end.

gpg_sign_erlang_verify() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        Data = <<"The brown fox">>,
        DataPath = filename:join(Tmp, "msg.txt"),
        ok = file:write_file(DataPath, Data),

        ok = gen_key(Home, rsa, "gpgsign-rsa@example.com"),
        {ok, PubRsaArmored} = gpg_export_public(Home, "gpgsign-rsa@example.com"),
        {ok, {rsa, PubRsa}} = openpgp_crypto:import_public(PubRsaArmored),
        SigRsaPath = filename:join(Tmp, "gpg-rsa.sig"),
        ok = gpg_sign_detached(Home, "gpgsign-rsa@example.com", DataPath, SigRsaPath),
        {ok, SigRsa} = file:read_file(SigRsaPath),
        ok = openpgp_detached_sig:verify(Data, SigRsa, {rsa, PubRsa}),

        ok = gen_key(Home, ed25519, "gpgsign-ed@example.com"),
        {ok, PubEdArmored} = gpg_export_public(Home, "gpgsign-ed@example.com"),
        {ok, {ed25519, PubEd32}} = openpgp_crypto:import_public(PubEdArmored),
        SigEdPath = filename:join(Tmp, "gpg-ed.sig"),
        ok = gpg_sign_detached(Home, "gpgsign-ed@example.com", DataPath, SigEdPath),
        {ok, SigEd} = file:read_file(SigEdPath),
        ok = openpgp_detached_sig:verify(Data, SigEd, {ed25519, PubEd32})
    after
        Cleanup()
    end.

erlang_clearsign_gpg_verify() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        Text = <<"The brown fox\n">>,
        MsgPath = filename:join(Tmp, "msg.txt"),
        ok = file:write_file(MsgPath, Text),

        % RSA
        {PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
        {ok, PubArmoredRsa, FprRsa} =
            openpgp_crypto:export_public({rsa, PubRsa}, #{
                userid => <<"Clear RSA <clear-rsa@example.com>">>,
                signing_key => PrivRsa
            }),
        ok = gpg_import_public(Home, PubArmoredRsa),
        {ok, ClearRsa} = openpgp_cleartext:sign(Text, {rsa, PrivRsa}, #{hash => sha512, issuer_fpr => FprRsa}),
        ClearRsaPath = filename:join(Tmp, "rsa-clearsigned.asc"),
        ok = file:write_file(ClearRsaPath, ClearRsa),
        ok = gpg_verify_clearsigned(Home, ClearRsaPath),

        % Ed25519
        {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
        {ok, PubArmoredEd, FprEd} =
            openpgp_crypto:export_public({ed25519, PubEd}, #{
                userid => <<"Clear Ed <clear-ed@example.com>">>,
                signing_key => PrivEd
            }),
        ok = gpg_import_public(Home, PubArmoredEd),
        {ok, ClearEd} = openpgp_cleartext:sign(Text, {ed25519, PrivEd}, #{hash => sha512, issuer_fpr => FprEd}),
        ClearEdPath = filename:join(Tmp, "ed-clearsigned.asc"),
        ok = file:write_file(ClearEdPath, ClearEd),
        ok = gpg_verify_clearsigned(Home, ClearEdPath)
    after
        Cleanup()
    end.

gpg_clearsign_erlang_verify() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        Text = <<"The brown fox\n">>,
        MsgPath = filename:join(Tmp, "msg.txt"),
        ok = file:write_file(MsgPath, Text),

        ok = gen_key(Home, rsa, "gpgclear-rsa@example.com"),
        ClearRsaPath = filename:join(Tmp, "gpg-rsa-clearsigned.asc"),
        ok = gpg_clearsign(Home, "gpgclear-rsa@example.com", MsgPath, ClearRsaPath),
        {ok, ClearRsa} = file:read_file(ClearRsaPath),
        {ok, PubRsaArmored} = gpg_export_public(Home, "gpgclear-rsa@example.com"),
        {ok, {rsa, PubRsa}} = openpgp_crypto:import_public(PubRsaArmored),
        ok = openpgp_cleartext:verify(ClearRsa, {rsa, PubRsa}),

        ok = gen_key(Home, ed25519, "gpgclear-ed@example.com"),
        ClearEdPath = filename:join(Tmp, "gpg-ed-clearsigned.asc"),
        ok = gpg_clearsign(Home, "gpgclear-ed@example.com", MsgPath, ClearEdPath),
        {ok, ClearEd} = file:read_file(ClearEdPath),
        {ok, PubEdArmored} = gpg_export_public(Home, "gpgclear-ed@example.com"),
        {ok, {ed25519, PubEd32}} = openpgp_crypto:import_public(PubEdArmored),
        ok = openpgp_cleartext:verify(ClearEd, {ed25519, PubEd32})
    after
        Cleanup()
    end.

crypto_to_gpg_secret() ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        % RSA secret export
        {_PubRsa, PrivRsa} = crypto:generate_key(rsa, {2048, 65537}),
        {ok, SecArmoredRsa, _FprRsa} =
            openpgp_crypto:export_secret({rsa, PrivRsa}, #{
                userid => <<"Secret RSA <secret-rsa@example.com>">>,
                signing_key => PrivRsa
            }),
        ok = gpg_import_secret(Home, SecArmoredRsa),

        % Ed25519 secret export
        {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
        {ok, SecArmoredEd, _FprEd} =
            openpgp_crypto:export_secret({ed25519, {PubEd, PrivEd}}, #{
                userid => <<"Secret Ed25519 <secret-ed@example.com>">>,
                signing_key => PrivEd
            }),
        ok = gpg_import_secret(Home, SecArmoredEd),

        {ok, SecList} = gpg(Home, ["--batch", "--yes", "--with-colons", "--list-secret-keys"]),
        ?assertNotEqual(nomatch, binary:match(SecList, <<"sec">>))
    after
        Cleanup()
    end.

roundtrip_key(Alg) ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home1 = filename:join(Tmp, "home1"),
        Home2 = filename:join(Tmp, "home2"),
        ok = file:make_dir(Home1),
        ok = file:change_mode(Home1, 8#700),
        ok = file:make_dir(Home2),
        ok = file:change_mode(Home2, 8#700),

        Email =
            case Alg of
                rsa -> "rsa-test@example.com";
                ed25519 -> "ed25519-test@example.com"
            end,
        ok = gen_key(Home1, Alg, Email),

        {ok, Armored1} = gpg_export_public(Home1, Email),
        {ok, #{packets := Packets}} = gpg_keys:decode(Armored1),
        Armored2 = gpg_keys:encode_public(Packets),

        ok = gpg_import_public(Home2, Armored2),

        {ok, Fpr1} = gpg_fingerprint(Home1, Email),
        {ok, Fpr2} = gpg_fingerprint(Home2, Email),
        ?assertEqual(Fpr1, Fpr2)
    after
        Cleanup()
    end.

erlang_to_gpg_import(Alg) ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Home = filename:join(Tmp, "home"),
        ok = file:make_dir(Home),
        ok = file:change_mode(Home, 8#700),

        UserId =
            case Alg of
                rsa -> <<"Erlang RSA <erlang-rsa@example.com>">>;
                ed25519 -> <<"Erlang Ed25519 <erlang-ed25519@example.com>">>
            end,

        KeyBlock =
            case Alg of
                rsa -> openpgp_keygen:rsa(UserId);
                ed25519 -> openpgp_keygen:ed25519(UserId)
            end,

        PubArmored = gpg_keys:encode_public(maps:get(public_packets, KeyBlock)),
        SecArmored = gpg_keys:encode_private(maps:get(secret_packets, KeyBlock)),

        ok = gpg_import_public(Home, PubArmored),
        ok = gpg_import_secret(Home, SecArmored),

        {ok, FprGpg} = gpg_first_fingerprint(Home),
        FprExpectedHex = hex_lower(maps:get(fingerprint, KeyBlock)),
        ?assertEqual(FprExpectedHex, string:lowercase(binary_to_list(FprGpg))),

        % verify secret key exists
        {ok, SecList} = gpg(Home, ["--batch", "--yes", "--with-colons", "--list-secret-keys"]),
        ?assertNotEqual(nomatch, binary:match(SecList, <<"sec">>))
    after
        Cleanup()
    end.

%% gpg helpers

gen_key(Home, rsa, Email) ->
    Batch = iolist_to_binary([
        "%no-protection\n",
        "Key-Type: RSA\n",
        "Key-Length: 2048\n",
        "Name-Real: Test RSA\n",
        "Name-Email: ", Email, "\n",
        "Expire-Date: 0\n",
        "%commit\n"
    ]),
    gpg_genkey_batch(Home, Batch);
gen_key(Home, ed25519, Email) ->
    % Works on modern GnuPG. If not supported, we skip.
    Batch = iolist_to_binary([
        "%no-protection\n",
        "Key-Type: eddsa\n",
        "Key-Curve: ed25519\n",
        "Name-Real: Test Ed25519\n",
        "Name-Email: ", Email, "\n",
        "Expire-Date: 0\n",
        "%commit\n"
    ]),
    case gpg_genkey_batch(Home, Batch) of
        ok -> ok;
        {skip, _} = Skip -> Skip;
        {error, {gpg_failed, _Status, Out}} ->
            % Backwards-compat: treat curve-not-supported as skip.
            case binary:match(Out, <<"ed25519">>) of
                nomatch -> error({gpg_failed, Out});
                _ -> {skip, "GnuPG does not appear to support Ed25519 key generation in batch mode in this environment"}
            end
    end.

gen_key_signing_subkey(Home, rsa, Email) ->
    % Primary: cert-only. Subkey: signing.
    Batch = iolist_to_binary([
        "%no-protection\n",
        "Key-Type: RSA\n",
        "Key-Length: 2048\n",
        "Key-Usage: cert\n",
        "Subkey-Type: RSA\n",
        "Subkey-Length: 2048\n",
        "Subkey-Usage: sign\n",
        "Name-Real: Test RSA Subkey\n",
        "Name-Email: ", Email, "\n",
        "Expire-Date: 0\n",
        "%commit\n"
    ]),
    gpg_genkey_batch(Home, Batch);
gen_key_signing_subkey(Home, ed25519, Email) ->
    % Primary: cert-only. Subkey: signing (Ed25519). May not be supported on older GnuPG.
    Batch = iolist_to_binary([
        "%no-protection\n",
        "Key-Type: eddsa\n",
        "Key-Curve: ed25519\n",
        "Key-Usage: cert\n",
        "Subkey-Type: eddsa\n",
        "Subkey-Curve: ed25519\n",
        "Subkey-Usage: sign\n",
        "Name-Real: Test Ed25519 Subkey\n",
        "Name-Email: ", Email, "\n",
        "Expire-Date: 0\n",
        "%commit\n"
    ]),
    case gpg_genkey_batch(Home, Batch) of
        ok ->
            ok;
        {error, {gpg_failed, _Status, Out}} ->
            case binary:match(Out, <<"ed25519">>) of
                nomatch -> error({gpg_failed, Out});
                _ -> {skip, "GnuPG does not appear to support Ed25519 subkey generation in batch mode in this environment"}
            end;
        {skip, _} = Skip ->
            Skip
    end.

gpg_genkey_batch(Home, BatchFileContent) ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        BatchPath = filename:join(Tmp, "genkey.batch"),
        ok = file:write_file(BatchPath, BatchFileContent),
        case gpg(Home, ["--batch", "--yes", "--gen-key", BatchPath]) of
            {ok, _} -> ok;
            {error, {gpg_failed, _Status, Out}} ->
                % If gpg returns non-zero because algo unsupported, the caller can decide to skip.
                {error, {gpg_failed, 1, Out}};
            {error, _} = Err -> Err
        end
    after
        Cleanup()
    end.

gpg_export_public(Home, Email) ->
    gpg(Home, ["--batch", "--yes", "--armor", "--export", Email]).

gpg_import_public(Home, ArmoredBin) ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Path = filename:join(Tmp, "pub.asc"),
        ok = file:write_file(Path, ArmoredBin),
        case gpg(Home, ["--batch", "--yes", "--import", Path]) of
            {ok, _} -> ok;
            {error, _} = Err -> error(Err)
        end
    after
        Cleanup()
    end.

gpg_import_secret(Home, ArmoredBin) ->
    {Tmp, Cleanup} = mktemp_dir(),
    try
        Path = filename:join(Tmp, "sec.asc"),
        ok = file:write_file(Path, ArmoredBin),
        case gpg(Home, ["--batch", "--yes", "--import", Path]) of
            {ok, _} -> ok;
            {error, _} = Err -> error(Err)
        end
    after
        Cleanup()
    end.

gpg_sign_detached(Home, Email, DataPath, SigPath) ->
    % Use binary mode detached signature, output armored signature to SigPath.
    case gpg(Home, ["--batch", "--yes", "--local-user", Email, "--armor", "--detach-sign", "--output", SigPath, DataPath]) of
        {ok, _} -> ok;
        {error, _} = Err -> error(Err)
    end.

gpg_first_secret_subkey_keyid(Home, Email) ->
    case gpg(Home, ["--batch", "--yes", "--with-colons", "--list-secret-keys", Email]) of
        {ok, Out} ->
            case first_keyid_by_prefix(Out, <<"ssb">>) of
                {ok, KeyId} -> KeyId;
                error -> error({no_secret_subkey, Out})
            end;
        {error, _} = Err ->
            error(Err)
    end.

first_keyid_by_prefix(Out, Prefix) when is_binary(Out), is_binary(Prefix) ->
    Lines = binary:split(Out, <<"\n">>, [global]),
    first_keyid_by_prefix_lines(Lines, Prefix).

first_keyid_by_prefix_lines([], _Prefix) ->
    error;
first_keyid_by_prefix_lines([L | Rest], Prefix) ->
    case binary:split(L, <<":">>, [global]) of
        [P | Fields] when P =:= Prefix ->
            % pub/sec/sub/ssb line: field 5 is keyid (1-based), i.e. 4th element in Fields
            case length(Fields) >= 4 of
                true -> {ok, lists:nth(4, Fields)};
                false -> first_keyid_by_prefix_lines(Rest, Prefix)
            end;
        _ ->
            first_keyid_by_prefix_lines(Rest, Prefix)
    end.

pick_signing_subkey_pub(Bundle) ->
    Subkeys = maps:get(subkeys, Bundle, []),
    Signing =
        [maps:get(pub, S) || S <- Subkeys, (maps:get(flags, S, 0) band 16#02) =:= 16#02],
    case Signing of
        [Pub | _] -> {ok, Pub};
        [] ->
            case Subkeys of
                [S0 | _] -> {ok, maps:get(pub, S0)};
                [] -> {error, no_subkeys}
            end
    end.

gpg_verify_detached(Home, SigPath, DataPath) ->
    case gpg(Home, ["--batch", "--yes", "--verify", SigPath, DataPath]) of
        {ok, _} -> ok;
        {error, _} = Err -> error(Err)
    end.

gpg_clearsign(Home, Email, DataPath, OutPath) ->
    case gpg(Home, ["--batch", "--yes", "--local-user", Email, "--clearsign", "--output", OutPath, DataPath]) of
        {ok, _} -> ok;
        {error, _} = Err -> error(Err)
    end.

gpg_verify_clearsigned(Home, ClearPath) ->
    case gpg(Home, ["--batch", "--yes", "--verify", ClearPath]) of
        {ok, _} -> ok;
        {error, _} = Err -> error(Err)
    end.

gpg_fingerprint(Home, Email) ->
    case gpg(Home, ["--batch", "--yes", "--with-colons", "--fingerprint", Email]) of
        {ok, Out} ->
            case first_fpr(Out) of
                {ok, Fpr} -> {ok, Fpr};
                error -> {error, {no_fingerprint, Out}}
            end;
        {error, _} = Err ->
            Err
    end.

gpg_first_fingerprint(Home) ->
    case gpg(Home, ["--batch", "--yes", "--with-colons", "--fingerprint"]) of
        {ok, Out} ->
            case first_fpr(Out) of
                {ok, Fpr} -> {ok, Fpr};
                error -> {error, {no_fingerprint, Out}}
            end;
        {error, _} = Err ->
            Err
    end.

first_fpr(Out) ->
    Lines = binary:split(Out, <<"\n">>, [global]),
    first_fpr_lines(Lines).

first_fpr_lines([]) ->
    error;
first_fpr_lines([L | Rest]) ->
    % fpr:::::::::FINGERPRINT:
    case binary:split(L, <<":">>, [global]) of
        [<<"fpr">> | Fields] ->
            case lists:reverse(Fields) of
                [<<>> | _] ->
                    % last element empty due to trailing ':'
                    % fingerprint is second last
                    case Fields of
                        _ ->
                            Fpr = lists:nth(length(Fields) - 1, Fields),
                            {ok, Fpr}
                    end;
                [Fpr | _] ->
                    {ok, Fpr}
            end;
        _ ->
            first_fpr_lines(Rest)
    end.

gpg(Home, Args) ->
    Gpg = os:find_executable("gpg"),
    Extra = gpg_extra_args(Gpg),
    Port =
        open_port(
            {spawn_executable, Gpg},
            [
                binary,
                exit_status,
                stderr_to_stdout,
                use_stdio,
                hide,
                {args, ["--no-options", "--no-tty"] ++ Extra ++ ["--homedir", Home | Args]}
            ]
        ),
    collect(Port, <<>>).

gpg_extra_args(Gpg) ->
    % GnuPG 2.3/2.4 can use keyboxd by default; some CI images break it.
    % Only pass --no-use-keyboxd if the gpg binary supports it.
    case gpg_supports_flag(Gpg, "--no-use-keyboxd") of
        true -> ["--no-use-keyboxd"];
        false -> []
    end.

gpg_supports_flag(Gpg, Flag) ->
    Key = {?MODULE, {gpg_flag, Flag}},
    case persistent_term:get(Key, undefined) of
        undefined ->
            Supported =
                case open_port({spawn_executable, Gpg}, [binary, exit_status, stderr_to_stdout, use_stdio, hide, {args, [Flag, "--version"]}]) of
                    Port ->
                        case collect(Port, <<>>) of
                            {ok, _} -> true;
                            {error, _} -> false
                        end
                end,
            persistent_term:put(Key, Supported),
            Supported;
        V ->
            V
    end.

collect(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            collect(Port, <<Acc/binary, Data/binary>>);
        {Port, {exit_status, 0}} ->
            {ok, Acc};
        {Port, {exit_status, Status}} ->
            maybe_debug_gpg_failure(Status, Acc),
            {error, {gpg_failed, Status, Acc}}
    after 120000 ->
        catch port_close(Port),
        {error, timeout}
    end.

maybe_debug_gpg_failure(Status, Out) ->
    case os:getenv("GPG_IT_DEBUG") of
        "1" ->
            io:format("gpg failed status=~p~n~s~n", [Status, Out]),
            ok;
        "true" ->
            io:format("gpg failed status=~p~n~s~n", [Status, Out]),
            ok;
        _ ->
            ok
    end.

hex_lower(Bin) when is_binary(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B:8>> <= Bin]).

mktemp_dir() ->
    Base =
        case os:getenv("TMPDIR") of
            false -> "/tmp";
            "" -> "/tmp";
            D -> D
        end,
    Name = "gpg_it_" ++ integer_to_list(erlang:unique_integer([positive, monotonic])),
    Dir = filename:join(Base, Name),
    ok = file:make_dir(Dir),
    ok = file:change_mode(Dir, 8#700),
    Cleanup = fun() -> rm_rf(Dir) end,
    {Dir, Cleanup}.

rm_rf(Path) ->
    case file:list_dir(Path) of
        {ok, Entries} ->
            lists:foreach(
                fun(E) ->
                    P = filename:join(Path, E),
                    case filelib:is_dir(P) of
                        true -> rm_rf(P);
                        false -> catch file:delete(P), ok
                    end
                end,
                Entries
            ),
            catch file:del_dir(Path),
            ok;
        {error, _} ->
            ok
    end.


