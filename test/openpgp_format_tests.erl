%%% EUnit tests for OpenPGP format helpers.
-module(openpgp_format_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

crc24_test() ->
    % CRC-24/OPENPGP check value for "123456789" is 0x21CF02
    ?assertEqual(16#21CF02, openpgp_crc24:crc24(<<"123456789">>)).

armor_roundtrip_test() ->
    Data = <<0,1,2,3,4,5,6,7,8,9,255>>,
    Armored = openpgp_armor:encode(<<"PGP PUBLIC KEY BLOCK">>, Data),
    {ok, #{type := Type, data := Data2}} = openpgp_armor:decode(Armored),
    ?assertEqual(<<"PGP PUBLIC KEY BLOCK">>, Type),
    ?assertEqual(Data, Data2).

packets_roundtrip_test() ->
    % Build a tiny "packet" (tag 63) with small body and ensure encode/decode works.
    P = #{tag => 63, format => new, body => <<"abc">>},
    Bin = openpgp_packets:encode([P]),
    {ok, [P2]} = openpgp_packets:decode(Bin),
    ?assertEqual(63, maps:get(tag, P2)),
    ?assertEqual(<<"abc">>, maps:get(body, P2)).

malformed_signature_test() ->
    Data = <<"The brown fox">>,
    % Not a valid armor and not valid packet framing either.
    BadSig = <<"not-a-signature">>,
    ?assertEqual({error, #{reason => malformed_signature, message => <<"malformed signature">>}},
                 openpgp_detached_sig:verify(Data, BadSig, {ed25519, <<0:256>>})).

binary_detached_signature_test() ->
    Data = <<"The brown fox">>,
    {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
    {ok, SigBin} = openpgp_detached_sig:sign(Data, {ed25519, PrivEd}, #{hash => sha256, armor => false}),
    ?assertEqual(nomatch, binary:match(SigBin, <<"BEGIN PGP SIGNATURE">>)),
    ?assertEqual(ok, openpgp_detached_sig:verify(Data, SigBin, {ed25519, PubEd})).

public_key_created_info_test() ->
    Now1 = erlang:system_time(second),
    KB = openpgp_keygen:ed25519(<<"Test <test@example.com>">>),
    Pub = gpg_keys:encode_public(maps:get(public_packets, KB)),
    {ok, #{created := Created, alg := Alg}} = openpgp_crypto:public_key_info(Pub),
    Now2 = erlang:system_time(second),
    ?assertEqual(ed25519, Alg),
    ?assert(Created >= Now1),
    ?assert(Created =< Now2).

import_public_key_internal_formats_test() ->
    % RSA
    {PubRsa, _PrivRsa} = crypto:generate_key(rsa, {1024, 65537}),
    {ok, ArmoredRsa, _FprRsa} =
        openpgp_crypto:export_public({rsa, PubRsa}, #{userid => <<"T <t@e>">>}),
    {ok, RsaRec} = openpgp_crypto:import_public_key(ArmoredRsa),
    ?assertMatch(#'RSAPublicKey'{}, RsaRec),

    % Ed25519
    {PubEd, _PrivEd} = crypto:generate_key(eddsa, ed25519),
    {ok, ArmoredEd, _FprEd} =
        openpgp_crypto:export_public({ed25519, PubEd}, #{userid => <<"T <t@e>">>}),
    {ok, {#'ECPoint'{point = PubEd2}, {namedCurve, _}}} = openpgp_crypto:import_public_key(ArmoredEd),
    ?assertEqual(PubEd, PubEd2).

import_public_bundle_key_formats_test() ->
    {PrimaryPub, PrimaryPriv} = crypto:generate_key(eddsa, ed25519),
    {SubPub, SubPriv} = crypto:generate_key(eddsa, ed25519),
    {ok, PubKeyBlock, #{subkey_fpr := SubFpr}} =
        openpgp_crypto:export_public_with_subkey(
            {ed25519, PrimaryPub},
            {ed25519, SubPub},
            #{
                userid => <<"Bundle <bundle@example.com>">>,
                signing_key => PrimaryPriv,
                subkey_signing_key => SubPriv,
                subkey_flags => [sign]
            }
        ),

    {ok, Bundle} = openpgp_crypto:import_public_bundle_key(PubKeyBlock),
    ?assertMatch({#'ECPoint'{}, {namedCurve, _}}, maps:get(primary, Bundle)),
    Subkeys = maps:get(subkeys, Bundle),
    [#{pub := {#'ECPoint'{}, {namedCurve, _}}}] = [S || S <- Subkeys, maps:get(fpr, S) =:= SubFpr].

primary_key_flags_export_test() ->
    {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
    {ok, Armored, _Fpr} =
        openpgp_crypto:export_public(
            {ed25519, PubEd},
            #{userid => <<"T <t@e>">>, signing_key => PrivEd, primary_key_flags => [certify, sign, auth]}
        ),
    {ok, #{packets := Packets}} = gpg_keys:decode(Armored),
    Flags = primary_key_flags_from_packets(Packets),
    ?assertEqual(16#23, Flags).

primary_key_expires_export_test() ->
    {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
    {ok, Armored, _Fpr} =
        openpgp_crypto:export_public(
            {ed25519, PubEd},
            #{userid => <<"T <t@e>">>, signing_key => PrivEd, primary_expires => 86400}
        ),
    {ok, #{packets := Packets}} = gpg_keys:decode(Armored),
    Expires = primary_key_expiration_from_packets(Packets),
    ?assertEqual(86400, Expires).

subkey_expires_export_test() ->
    {PrimaryPub, PrimaryPriv} = crypto:generate_key(eddsa, ed25519),
    {SubPub, SubPriv} = crypto:generate_key(eddsa, ed25519),
    {ok, PubKeyBlock, _} =
        openpgp_crypto:export_public_with_subkey(
            {ed25519, PrimaryPub},
            {ed25519, SubPub},
            #{
                userid => <<"Bundle <bundle@example.com>">>,
                signing_key => PrimaryPriv,
                subkey_signing_key => SubPriv,
                subkey_flags => [sign],
                subkey_expires => 172800
            }
        ),
    {ok, #{packets := Packets}} = gpg_keys:decode(PubKeyBlock),
    Expires = subkey_expiration_from_packets(Packets),
    ?assertEqual(172800, Expires).

subkey_pub_by_keyid_test() ->
    {PrimaryPub, PrimaryPriv} = crypto:generate_key(eddsa, ed25519),
    {SubPub, SubPriv} = crypto:generate_key(eddsa, ed25519),
    {ok, PubKeyBlock, #{subkey_fpr := SubFpr}} =
        openpgp_crypto:export_public_with_subkey(
            {ed25519, PrimaryPub},
            {ed25519, SubPub},
            #{
                userid => <<"Bundle <bundle@example.com>">>,
                signing_key => PrimaryPriv,
                subkey_signing_key => SubPriv,
                subkey_flags => [sign]
            }
        ),
    {ok, Bundle} = openpgp_crypto:import_public_bundle(PubKeyBlock),
    Subkeys = maps:get(subkeys, Bundle),
    [Subkey] = [S || S <- Subkeys, maps:get(fpr, S) =:= SubFpr],
    KeyId = maps:get(keyid, Subkey),
    {ok, Pub} = openpgp_crypto:subkey_pub_by_keyid(Bundle, KeyId),
    ?assertEqual(maps:get(pub, Subkey), Pub).

primary_key_flags_from_packets(Packets) ->
    SigBodies = [maps:get(body, P) || P <- Packets, maps:get(tag, P) =:= 2],
    case find_selfsig_flags(SigBodies) of
        {ok, Flags} -> Flags;
        error -> error(no_primary_key_flags_found)
    end.

find_selfsig_flags([]) ->
    error;
find_selfsig_flags([Body | Rest]) ->
    case parse_v4_sig_info(Body) of
        {ok, #{sig_type := 16#13, hashed_sub := Hashed}} ->
            case find_sig_subpacket(27, Hashed) of
                {ok, <<Flags:8, _/binary>>} -> {ok, Flags};
                _ -> find_selfsig_flags(Rest)
            end;
        _ ->
            find_selfsig_flags(Rest)
    end.

primary_key_expiration_from_packets(Packets) ->
    SigBodies = [maps:get(body, P) || P <- Packets, maps:get(tag, P) =:= 2],
    case find_selfsig_expiration(SigBodies) of
        {ok, Exp} -> Exp;
        error -> error(no_primary_key_expiration_found)
    end.

find_selfsig_expiration([]) ->
    error;
find_selfsig_expiration([Body | Rest]) ->
    case parse_v4_sig_info(Body) of
        {ok, #{sig_type := 16#13, hashed_sub := Hashed}} ->
            case find_sig_subpacket(9, Hashed) of
                {ok, <<Exp:32/big-unsigned, _/binary>>} -> {ok, Exp};
                _ -> find_selfsig_expiration(Rest)
            end;
        _ ->
            find_selfsig_expiration(Rest)
    end.

subkey_expiration_from_packets(Packets) ->
    SigBodies = [maps:get(body, P) || P <- Packets, maps:get(tag, P) =:= 2],
    case find_subkey_binding_expiration(SigBodies) of
        {ok, Exp} -> Exp;
        error -> error(no_subkey_expiration_found)
    end.

find_subkey_binding_expiration([]) ->
    error;
find_subkey_binding_expiration([Body | Rest]) ->
    case parse_v4_sig_info(Body) of
        {ok, #{sig_type := 16#18, hashed_sub := Hashed}} ->
            case find_sig_subpacket(9, Hashed) of
                {ok, <<Exp:32/big-unsigned, _/binary>>} -> {ok, Exp};
                _ -> find_subkey_binding_expiration(Rest)
            end;
        _ ->
            find_subkey_binding_expiration(Rest)
    end.

parse_v4_sig_info(
    <<4:8, SigType:8, _PkAlgId:8, _HashAlgId:8, HashedLen:16/big-unsigned, Hashed:HashedLen/binary,
      UnhashedLen:16/big-unsigned, _Unhashed:UnhashedLen/binary, _Hash16:2/binary, _Rest/binary>>
) ->
    {ok, #{sig_type => SigType, hashed_sub => Hashed}};
parse_v4_sig_info(_Other) ->
    {error, bad_signature_packet}.

find_sig_subpacket(Type, Bin) when is_integer(Type), is_binary(Bin) ->
    find_sig_subpacket(Type, Bin, error).

find_sig_subpacket(_Type, <<>>, Default) ->
    Default;
find_sig_subpacket(Type, <<Len:8, T:8, Rest/binary>>, Default) when Len >= 1 ->
    BodyLen = Len - 1,
    case Rest of
        <<Body:BodyLen/binary, Tail/binary>> ->
            case T =:= Type of
                true -> {ok, Body};
                false -> find_sig_subpacket(Type, Tail, Default)
            end;
        _ ->
            Default
    end.

subkey_flags_to_atoms_test() ->
    ?assertEqual([], openpgp_crypto:subkey_flags_to_atoms(undefined)),
    ?assertEqual([], openpgp_crypto:subkey_flags_to_atoms(0)),
    ?assertEqual([sign], openpgp_crypto:subkey_flags_to_atoms(16#02)),
    ?assertEqual([encrypt_communication, encrypt_storage], openpgp_crypto:subkey_flags_to_atoms(16#0C)),
    ?assertEqual([sign, auth], openpgp_crypto:subkey_flags_to_atoms(16#22)).


