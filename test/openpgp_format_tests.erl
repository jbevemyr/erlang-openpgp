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



%% ---- review 2026-09: hashes, canonicalization, verification checks, bindings

sha384_roundtrip_test() ->
    Data = <<"sha384 please">>,
    {PubEd, PrivEd} = crypto:generate_key(eddsa, ed25519),
    {ok, Sig} = openpgp_detached_sig:sign(Data, {ed25519, PrivEd}, #{hash => sha384}),
    ?assertEqual(ok, openpgp_detached_sig:verify(Data, Sig, {ed25519, PubEd})),
    {ok, #{hash_alg := 9}} = openpgp_detached_sig:parse_signature(Sig).

unsupported_hash_is_an_error_test() ->
    {_Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    ?assertEqual({error, {unsupported_hash, sha1}},
                 openpgp_detached_sig:sign(<<"x">>, {ed25519, Priv}, #{hash => sha1})),
    ?assertEqual({error, {unsupported_hash, sha224}},
                 openpgp_detached_sig:sign(<<"x">>, {ed25519, Priv}, #{hash => sha224})).

%% A text signature normalizes line endings and nothing else.
text_signature_canonicalization_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    Opts = #{sig_type => 16#01},
    {ok, Sig} = openpgp_detached_sig:sign(<<"a \nb">>, {ed25519, Priv}, Opts),
    ?assertEqual(ok, openpgp_detached_sig:verify(<<"a \r\nb">>, Sig, {ed25519, Pub})),
    ?assertMatch({error, #{reason := bad_signature}},
                 openpgp_detached_sig:verify(<<"a\nb">>, Sig, {ed25519, Pub})),
    %% the caller can insist on a signature type
    ?assertMatch({error, #{detail := {unexpected_sig_type, 1}}},
                 openpgp_detached_sig:verify(<<"a \nb">>, Sig, {ed25519, Pub}, #{sig_type => 16#00})).

%% The cleartext framework strips trailing whitespace before signing and verifying.
cleartext_strips_trailing_whitespace_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {ok, Clear} = openpgp_cleartext:sign(<<"line one  \nline two\t\n">>, {ed25519, Priv}, #{}),
    ?assertEqual(ok, openpgp_cleartext:verify(Clear, {ed25519, Pub})).

verification_checks_test() ->
    Data = <<"checked">>,
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    Now = erlang:system_time(second),
    KB = openpgp_keygen:ed25519(<<"Checks <c@example.com>">>),
    Fpr = maps:get(fingerprint, KB),
    OtherFpr = crypto:hash(sha, <<"other">>),
    {ok, Sig} = openpgp_detached_sig:sign(Data, {ed25519, Priv},
                                          #{created => Now - 100, expires => 50, issuer_fpr => Fpr}),
    %% expired
    ?assertMatch({error, #{detail := signature_expired}},
                 openpgp_detached_sig:verify(Data, Sig, {ed25519, Pub}, #{now => Now})),
    %% fine when observed before expiry
    ?assertEqual(ok, openpgp_detached_sig:verify(Data, Sig, {ed25519, Pub}, #{now => Now - 80})),
    %% predates the key
    ?assertMatch({error, #{detail := signature_predates_key}},
                 openpgp_detached_sig:verify(Data, Sig, {ed25519, Pub}, #{now => Now - 80, key_created => Now})),
    %% names another issuer
    ?assertMatch({error, #{detail := issuer_mismatch}},
                 openpgp_detached_sig:verify(Data, Sig, {ed25519, Pub}, #{now => Now - 80, issuer_fpr => OtherFpr})),
    ?assertEqual(ok, openpgp_detached_sig:verify(Data, Sig, {ed25519, Pub}, #{now => Now - 80, issuer_fpr => Fpr})),
    %% from the future
    {ok, Sig2} = openpgp_detached_sig:sign(Data, {ed25519, Priv}, #{created => Now + 3600}),
    ?assertMatch({error, #{detail := signature_from_the_future}},
                 openpgp_detached_sig:verify(Data, Sig2, {ed25519, Pub}, #{now => Now})).

%% A key id (subpacket 16) starting with 0x04 is not mistaken for a v4 fingerprint.
issuer_keyid_with_0x04_prefix_test() ->
    Fpr = <<0:96, 4, 1, 2, 3, 4, 5, 6, 7>>,
    ?assert(openpgp_detached_sig:is_issuer({16, <<4, 1, 2, 3, 4, 5, 6, 7>>}, Fpr)),
    ?assert(openpgp_detached_sig:is_issuer({33, <<4, Fpr/binary>>}, Fpr)),
    ?assertNot(openpgp_detached_sig:is_issuer({33, <<4, 1, 2, 3, 4, 5, 6, 7>>}, Fpr)),
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {Created, KeyFpr} = keyid_0x04_fingerprint({ed25519, Pub}, 1700000000),
    {ok, Sig} = openpgp_detached_sig:sign(<<"x">>, {ed25519, Priv}, #{created => Created, issuer_fpr => KeyFpr}),
    ?assertEqual(ok, openpgp_detached_sig:verify(<<"x">>, Sig, {ed25519, Pub}, #{issuer_fpr => KeyFpr})).

keyid_0x04_fingerprint(Pub, Created) ->
    case openpgp_crypto:fingerprint(Pub, Created) of
        {ok, <<_:12/binary, 4, _/binary>> = Fpr} -> {Created, Fpr};
        {ok, _} -> keyid_0x04_fingerprint(Pub, Created + 1)
    end.

subpacket_lengths_test() ->
    Big = binary:copy(<<$x>>, 300),
    %% 2-octet length form for a 301-byte subpacket, then a 1-octet one
    Len = 301 - 192,
    Area = <<((Len bsr 8) + 192):8, (Len band 16#FF):8, 20:8, Big/binary, 2:8, 16:8, 7:8>>,
    ?assertEqual([{20, Big}, {16, <<7>>}], openpgp_detached_sig:sig_subpackets(Area)),
    %% critical bit is masked off
    ?assertEqual([{2, <<1, 2, 3, 4>>}], openpgp_detached_sig:sig_subpackets(<<5, 16#82, 1, 2, 3, 4>>)).

bundle() ->
    {PubP, PrivP} = crypto:generate_key(eddsa, ed25519),
    {PubS, PrivS} = crypto:generate_key(eddsa, ed25519),
    Opts = #{userid => <<"Bundle <b@example.com>">>, signing_key => PrivP,
             subkey_signing_key => PrivS, subkey_flags => 16#02},
    {ok, Armored, _} = openpgp_crypto:export_public_with_subkey({ed25519, PubP}, {ed25519, PubS}, Opts),
    {ok, #{packets := Packets}} = gpg_keys:decode(Armored),
    {Packets, PubS}.

bundle_import_verifies_bindings_test() ->
    {Packets, PubS} = bundle(),
    {ok, #{self_certified := true, subkeys := [Sub]}} =
        openpgp_crypto:import_public_bundle(openpgp_packets:encode(Packets)),
    ?assertEqual({ed25519, PubS}, maps:get(pub, Sub)),
    ?assertEqual(16#02, maps:get(flags, Sub)),
    %% [primary, uid, selfsig, subkey, binding]
    [Prim, Uid, SelfSig, SubPkt, Binding] = Packets,
    %% no self-certification: imported, but reported as such
    {ok, #{self_certified := false}} =
        openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, SubPkt, Binding])),
    %% a binding that does not verify (subkey body tampered) rejects the subkey
    <<4:8, Created:32, Tail/binary>> = maps:get(body, SubPkt),
    Tampered = SubPkt#{body => <<4:8, (Created + 1):32, Tail/binary>>},
    ?assertMatch({error, {unbound_subkey, _, _}},
                 openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, SelfSig, Tampered, Binding]))),
    %% a subkey without any binding is rejected too
    ?assertMatch({error, {unbound_subkey, _, no_binding_signature}},
                 openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, SelfSig, SubPkt]))),
    %% a self-certification that names the primary key but does not verify is an error
    <<SB1:20/binary, _:8, SBRest/binary>> = maps:get(body, SelfSig),
    BadSelf = SelfSig#{body => <<SB1/binary, 0:8, SBRest/binary>>},
    ?assertMatch({error, {invalid_self_certification, _, _}},
                 openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, BadSelf, SubPkt, Binding]))).

ed25519_private_tuple_without_public_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    Oid = pubkey_cert_records:namedCurves(ed25519),
    {ok, Armored, _} = openpgp_crypto:export_public_key(
        {'ECPrivateKey', 1, Priv, {namedCurve, Oid}, asn1_NOVALUE}, #{userid => <<"T <t@e>">>}),
    {ok, {ed25519, Pub}} = openpgp_crypto:import_public(Armored).

fingerprint_matches_export_test() ->
    {Pub, _} = crypto:generate_key(eddsa, ed25519),
    Created = 1700000000,
    {ok, _Armored, Fpr} = openpgp_crypto:export_public({ed25519, Pub}, #{userid => <<"F <f@e>">>, created => Created}),
    ?assertEqual({ok, Fpr}, openpgp_crypto:fingerprint({ed25519, Pub}, Created)).
