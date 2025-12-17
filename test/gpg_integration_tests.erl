%%% Integration tests against gpg.
%%%
%%% These tests require `gpg` installed and available in PATH.
%%% They generate keys inside isolated GNUPGHOME directories under /tmp.
-module(gpg_integration_tests).

-include_lib("eunit/include/eunit.hrl").

gpg_required_test_() ->
    case os:find_executable("gpg") of
        false ->
            {skip, "gpg saknas i PATH"};
        _ ->
            [
                {"gpg -> Erlang decode/encode -> gpg import (RSA)", fun rsa_roundtrip/0},
                {"gpg -> Erlang decode/encode -> gpg import (Ed25519)", fun ed25519_roundtrip/0},
                {"Erlang -> gpg import (RSA, public+secret)", fun erlang_rsa_to_gpg_import/0},
                {"Erlang -> gpg import (Ed25519, public+secret)", fun erlang_ed25519_to_gpg_import/0},
                {"gpg -> crypto-format (RSA/Ed25519)", fun gpg_to_crypto_public/0},
                {"crypto-format -> gpg import (public, RSA/Ed25519)", fun crypto_to_gpg_public/0}
                ,{"signera i Erlang och verifiera med gpg (RSA/Ed25519)", fun erlang_sign_gpg_verify/0}
                ,{"signera i gpg och verifiera i Erlang (RSA/Ed25519)", fun gpg_sign_erlang_verify/0}
                ,{"clearsign i Erlang och verifiera med gpg (RSA/Ed25519)", fun erlang_clearsign_gpg_verify/0}
                ,{"clearsign i gpg och verifiera i Erlang (RSA/Ed25519)", fun gpg_clearsign_erlang_verify/0}
                ,{"exportera secret key från crypto-format och importera i gpg (RSA/Ed25519)", fun crypto_to_gpg_secret/0}
            ]
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
                _ -> {skip, "GnuPG verkar inte stödja ed25519-nyckelgenerering i batchläge i denna miljö"}
            end
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
    Port =
        open_port(
            {spawn_executable, Gpg},
            [
                binary,
                exit_status,
                stderr_to_stdout,
                use_stdio,
                hide,
                {args, ["--no-options", "--no-tty", "--homedir", Home | Args]}
            ]
        ),
    collect(Port, <<>>).

collect(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            collect(Port, <<Acc/binary, Data/binary>>);
        {Port, {exit_status, 0}} ->
            {ok, Acc};
        {Port, {exit_status, Status}} ->
            {error, {gpg_failed, Status, Acc}}
    after 120000 ->
        catch port_close(Port),
        {error, timeout}
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


