%%% Signature and key validity: what verification and key block import
%%% accept beyond the cryptographic check.
-module(openpgp_validity_tests).

-include_lib("eunit/include/eunit.hrl").

-define(UID, <<"V <v@example.com>">>).

%% Document signatures

%% An RSA signature whose integer has a leading zero octet (1 in 256) has
%% a shorter MPI than the modulus.
rsa_signature_with_leading_zero_test() ->
    {[E, N], Priv} = crypto:generate_key(rsa, {1024, 65537}),
    {Data, Sig} = leading_zero_rsa_signature(Priv, 0),
    ?assertEqual(ok, openpgp_detached_sig:verify(Data, Sig, {rsa, [E, N]})).

leading_zero_rsa_signature(Priv, I) ->
    Data = integer_to_binary(I),
    {ok, Sig} = openpgp_detached_sig:sign(Data, {rsa, Priv}, #{hash => sha256, armor => false, created => 1700000000}),
    {ok, #{mpis := [<<Bits:16, _/binary>>]}} = openpgp_detached_sig:parse_signature(Sig),
    case Bits =< 1016 of
        true -> {Data, Sig};
        false -> leading_zero_rsa_signature(Priv, I + 1)
    end.

critical_subpackets_test_() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    Verify = fun(Hashed) ->
        openpgp_detached_sig:verify(<<"d">>, doc_sig(Priv, [created() | Hashed]), {ed25519, Pub})
    end,
    [
        ?_assertEqual(ok, Verify([openpgp_sig:subpacket(100, <<"x">>)])),
        ?_assertMatch({error, #{detail := {unknown_critical_subpacket, 100}}},
                      Verify([openpgp_sig:subpacket(16#80 bor 100, <<"x">>)])),
        %% a critical notation (20) and policy URI (26) are not understood
        ?_assertMatch({error, #{detail := {unknown_critical_subpacket, 20}}},
                      Verify([openpgp_sig:subpacket(16#80 bor 20, <<16#80, 0, 0, 0, 0, 1, 0, 1, "n", "v">>)])),
        ?_assertMatch({error, #{detail := {unknown_critical_subpacket, 26}}},
                      Verify([openpgp_sig:subpacket(16#80 bor 26, <<"https://example.com">>)])),
        %% a critical subpacket that is understood is fine
        ?_assertEqual(ok, Verify([openpgp_sig:subpacket(16#80 bor 3, <<0:32>>)]))
    ].

malformed_hashed_area_test_() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    Verify = fun(Hashed) -> openpgp_detached_sig:verify(<<"d">>, doc_sig(Priv, Hashed), {ed25519, Pub}) end,
    [
        %% a zero-length subpacket, then an expiration that must not be lost
        ?_assertMatch({error, #{reason := malformed_signature}},
                      Verify([created(), <<0>>, openpgp_sig:subpacket(3, <<1:32>>)])),
        %% a truncated subpacket at the end
        ?_assertMatch({error, #{reason := malformed_signature}}, Verify([created(), <<5, 3, 0>>]))
    ].

%% Of conflicting subpackets the last one counts.
last_subpacket_wins_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    Now = erlang:system_time(second),
    Sig = doc_sig(Priv, [created(), openpgp_sig:subpacket(3, <<0:32>>), openpgp_sig:subpacket(3, <<1:32>>)]),
    ?assertMatch({error, #{detail := signature_expired}},
                 openpgp_detached_sig:verify(<<"d">>, Sig, {ed25519, Pub}, #{now => Now + 10})).

multiple_signatures_test() ->
    {PubA, PrivA} = crypto:generate_key(eddsa, ed25519),
    {PubB, PrivB} = crypto:generate_key(eddsa, ed25519),
    {PubC, _} = crypto:generate_key(eddsa, ed25519),
    {ok, SigA} = openpgp_detached_sig:sign(<<"d">>, {ed25519, PrivA}, #{armor => false}),
    {ok, SigB} = openpgp_detached_sig:sign(<<"d">>, {ed25519, PrivB}, #{armor => false}),
    Both = openpgp_armor:encode(<<"PGP SIGNATURE">>, <<SigA/binary, SigB/binary>>),
    ?assertEqual(ok, openpgp_detached_sig:verify(<<"d">>, Both, {ed25519, PubA})),
    ?assertEqual(ok, openpgp_detached_sig:verify(<<"d">>, Both, {ed25519, PubB})),
    ?assertMatch({error, #{reason := bad_signature}}, openpgp_detached_sig:verify(<<"d">>, Both, {ed25519, PubC})),
    %% only signature packets belong in a signature block
    Uid = openpgp_packets:encode([#{tag => 13, format => new, body => ?UID}]),
    ?assertMatch({error, #{reason := malformed_signature}},
                 openpgp_detached_sig:verify(<<"d">>, <<SigA/binary, Uid/binary>>, {ed25519, PubA})).

key_expires_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {ok, Sig} = openpgp_detached_sig:sign(<<"d">>, {ed25519, Priv}, #{created => 1700000000}),
    ?assertEqual(ok, openpgp_detached_sig:verify(<<"d">>, Sig, {ed25519, Pub}, #{key_expires => 1700000001})),
    ?assertMatch({error, #{detail := key_expired}},
                 openpgp_detached_sig:verify(<<"d">>, Sig, {ed25519, Pub}, #{key_expires => 1700000000})).

sha224_and_sha3_verify_test_() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {PubR, PrivR} = crypto:generate_key(rsa, {1024, 65537}),
    [
        ?_assertEqual(ok, openpgp_detached_sig:verify(<<"d">>, doc_sig(ed25519, Priv, H, [created()]), {ed25519, Pub}))
     || H <- [{11, sha224}, {12, sha3_256}, {14, sha3_512}]
    ] ++
        [
            ?_assertEqual(ok, openpgp_detached_sig:verify(<<"d">>, doc_sig(rsa, PrivR, {11, sha224}, [created()]), {rsa, PubR})),
            ?_assertMatch({error, {unsupported_hash_alg, 2}},
                          openpgp_detached_sig:verify(<<"d">>, doc_sig(ed25519, Priv, {2, sha}, [created()]), {ed25519, Pub}))
        ].

%% Key signatures

%% Certifications are checked like document signatures, and one that fails
%% the checks does not certify.
certification_checks_test_() ->
    #{prim := Prim, uid := Uid, priv := Priv} = key(),
    Prefix = uid_prefix(Prim, ?UID),
    Import = fun(Hashed) ->
        Cert = openpgp_sig:key_signature(ed25519, #{priv => Priv}, 16#13, Prefix, Hashed, []),
        openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, Cert]))
    end,
    Certified = fun(Result) -> maps:get(userids, element(2, Result)) =/= [] end,
    [
        ?_assert(Certified(Import([created()]))),
        ?_assertNot(Certified(Import([]))),
        ?_assertNot(Certified(Import([openpgp_sig:subpacket(2, <<1:32>>), openpgp_sig:subpacket(3, <<1:32>>)]))),
        ?_assertNot(Certified(Import([created(), openpgp_sig:subpacket(16#80 bor 100, <<>>)]))),
        ?_assertNot(Certified(Import([openpgp_sig:subpacket(2, <<(erlang:system_time(second) + 3600):32>>)])))
    ].

primary_revoked_test() ->
    #{prim := Prim, uid := Uid, cert := Cert, priv := Priv} = key(),
    Rev = openpgp_sig:key_signature(ed25519, #{priv => Priv}, 16#20, key_prefix(Prim), [created()], []),
    ?assertEqual({error, key_revoked}, openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Rev, Uid, Cert]))),
    %% a revocation by another key does not count
    {_, Other} = crypto:generate_key(eddsa, ed25519),
    BadRev = openpgp_sig:key_signature(ed25519, #{priv => Other}, 16#20, key_prefix(Prim), [created()], []),
    ?assertMatch({ok, _}, openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, BadRev, Uid, Cert]))).

userid_revoked_test() ->
    #{prim := Prim, uid := Uid, priv := Priv} = key(),
    Prefix = uid_prefix(Prim, ?UID),
    Sig = fun(Type, Created) ->
        openpgp_sig:key_signature(ed25519, #{priv => Priv}, Type, Prefix, [openpgp_sig:subpacket(2, <<Created:32>>)], [])
    end,
    Import = fun(Sigs) ->
        {ok, #{userids := U}} = openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid | Sigs])),
        U
    end,
    Created = key_created(Prim),
    ?assertEqual([], Import([Sig(16#13, Created + 1), Sig(16#30, Created + 2)])),
    ?assertEqual([?UID], Import([Sig(16#13, Created + 3), Sig(16#30, Created + 2)])).

primary_expired_test() ->
    #{prim := Prim, uid := Uid, priv := Priv} = key(),
    Created = key_created(Prim),
    Cert = openpgp_sig:key_signature(
        ed25519, #{priv => Priv}, 16#13, uid_prefix(Prim, ?UID),
        [openpgp_sig:subpacket(2, <<(Created + 1):32>>), openpgp_sig:subpacket(9, <<100:32>>)], []
    ),
    Block = openpgp_packets:encode([Prim, Uid, Cert]),
    ?assertMatch({ok, #{primary_expires := E}} when E =:= Created + 100,
                 openpgp_crypto:import_public_bundle(Block, #{now => Created + 99})),
    ?assertEqual({error, key_expired}, openpgp_crypto:import_public_bundle(Block, #{now => Created + 100})),
    %% a direct-key signature takes precedence
    Direct = openpgp_sig:key_signature(
        ed25519, #{priv => Priv}, 16#1F, key_prefix(Prim), [openpgp_sig:subpacket(2, <<(Created + 1):32>>)], []
    ),
    ?assertMatch({ok, #{primary_expires := undefined}},
                 openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Direct, Uid, Cert]),
                                                     #{now => Created + 100})).

primary_userid_first_test() ->
    #{prim := Prim, uid := Uid, cert := Cert, priv := Priv} = key(),
    Uid2 = #{tag => 13, format => new, body => <<"W <w@example.com>">>},
    Cert2 = openpgp_sig:key_signature(
        ed25519, #{priv => Priv}, 16#13, uid_prefix(Prim, <<"W <w@example.com>">>),
        [openpgp_sig:subpacket(2, <<(key_created(Prim) + 1):32>>), openpgp_sig:subpacket(25, <<1>>)], []
    ),
    ?assertMatch({ok, #{userids := [<<"W <w@example.com>">>, ?UID]}},
                 openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, Cert, Uid2, Cert2]))).

subkey_revoked_and_expired_test() ->
    #{prim := Prim, uid := Uid, cert := Cert, priv := Priv} = key(),
    PrimBody = maps:get(body, Prim),
    {SubPub, _} = crypto:generate_key(eddsa, ed25519),
    {ok, SubBlock, _} = openpgp_crypto:export_public({ed25519, SubPub}, #{userid => <<>>}),
    {ok, #{packets := [#{body := SubBody} | _]}} = gpg_keys:decode(SubBlock),
    Sub = #{tag => 14, format => new, body => SubBody},
    SubCreated = key_created(Sub),
    Prefix = iolist_to_binary([key_prefix(Prim), key_prefix(Sub)]),
    Binding = fun(Opts) ->
        #{packet := B} = openpgp_sig:subkey_binding(ed25519, #{priv => Priv}, PrimBody, SubBody, Opts#{subkey_flags => 16#0C}),
        B
    end,
    Import = fun(Sigs, Now) ->
        openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, Cert, Sub | Sigs]), #{now => Now})
    end,
    Now = erlang:system_time(second),
    Rev = openpgp_sig:key_signature(ed25519, #{priv => Priv}, 16#28, Prefix, [created()], []),
    ?assertMatch({ok, #{subkeys := [], rejected_subkeys := [#{reason := revoked}]}}, Import([Binding(#{}), Rev], Now)),
    Expiring = Binding(#{key_expiration => 100}),
    ?assertMatch({ok, #{subkeys := [#{expires := E}]}} when E =:= SubCreated + 100, Import([Expiring], SubCreated + 99)),
    ?assertMatch({ok, #{subkeys := [], rejected_subkeys := [#{reason := expired}]}}, Import([Expiring], SubCreated + 100)).

latest_binding_wins_test() ->
    #{prim := Prim, uid := Uid, cert := Cert, priv := Priv} = key(),
    {SubPub, _} = crypto:generate_key(eddsa, ed25519),
    {ok, SubBlock, _} = openpgp_crypto:export_public({ed25519, SubPub}, #{userid => <<>>, created => 1600000000}),
    {ok, #{packets := [#{body := SubBody} | _]}} = gpg_keys:decode(SubBlock),
    Sub = #{tag => 14, format => new, body => SubBody},
    Binding = fun(Created, Flags) ->
        #{packet := B} = openpgp_sig:subkey_binding(
            ed25519, #{priv => Priv}, maps:get(body, Prim), SubBody, #{created => Created, subkey_flags => Flags}
        ),
        B
    end,
    Created = key_created(Prim),
    Import = fun(Sigs) ->
        {ok, #{subkeys := [#{flags := F}]}} =
            openpgp_crypto:import_public_bundle(openpgp_packets:encode([Prim, Uid, Cert, Sub | Sigs])),
        F
    end,
    ?assertEqual(16#04, Import([Binding(Created + 2, 16#04), Binding(Created + 1, 16#08)])),
    ?assertEqual(16#04, Import([Binding(Created + 1, 16#08), Binding(Created + 2, 16#04)])).

%% Malformed input gives an error, never a crash.
truncated_key_block_test_() ->
    [
        ?_assertMatch({error, _}, openpgp_crypto:import_public_bundle(<<16#C6, 255, 1>>)),
        ?_assertMatch({error, _}, openpgp_crypto:import_public_bundle(<<16#C6, 200>>))
    ].

%% Export

export_errors_test_() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {_, OtherPriv} = crypto:generate_key(eddsa, ed25519),
    [
        ?_assertEqual({error, missing_signing_key_for_primary_flags},
                      openpgp_crypto:export_public({ed25519, Pub}, #{userid => ?UID, primary_expires => 10})),
        ?_assertEqual({error, bad_signing_key},
                      openpgp_crypto:export_public({ed25519, Pub}, #{userid => ?UID, signing_key => <<1, 2>>})),
        ?_assertEqual({error, signing_key_mismatch},
                      openpgp_crypto:export_public({ed25519, Pub}, #{userid => ?UID, signing_key => OtherPriv})),
        ?_assertEqual({error, signing_key_mismatch},
                      openpgp_crypto:export_secret({ed25519, {Pub, Priv}}, #{userid => ?UID, signing_key => OtherPriv})),
        ?_assertMatch({error, {bad_subkey_binding, invalid_back_signature}},
                      openpgp_crypto:export_public_with_subkey(
                          {ed25519, Pub}, {ed25519, Pub},
                          #{userid => ?UID, signing_key => Priv, subkey_signing_key => OtherPriv}
                      ))
    ].

export_secret_self_signature_options_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {ok, Armored, _} = openpgp_crypto:export_secret(
        {ed25519, {Pub, Priv}}, #{userid => ?UID, signing_key => Priv, primary_key_flags => [certify, sign], primary_expires => 3600}
    ),
    {ok, #{packets := [_, _, #{body := SigBody}]}} = gpg_keys:decode(Armored),
    {ok, #{hashed_sub := Hashed}} = openpgp_detached_sig:parse_signature(openpgp_packets:encode([#{tag => 2, format => new, body => SigBody}])),
    ?assertEqual({ok, <<16#03>>}, openpgp_detached_sig:sig_subpacket(27, Hashed)),
    ?assertEqual({ok, <<3600:32>>}, openpgp_detached_sig:sig_subpacket(9, Hashed)),
    %% preferences and features (RFC 9580 5.2.3.10-5.2.3.32)
    [?assertMatch({ok, _}, openpgp_detached_sig:sig_subpacket(T, Hashed)) || T <- [11, 21, 22, 30]].

rsa_secret_prime_order_test() ->
    {_, Priv} = crypto:generate_key(rsa, {1024, 65537}),
    {ok, Armored, _} = openpgp_crypto:export_secret({rsa, Priv}, #{userid => ?UID, signing_key => Priv}),
    {ok, #{packets := [#{tag := 5, body := Body} | _]}} = gpg_keys:decode(Armored),
    {ok, PubBody} = public_part(Body),
    <<_:(byte_size(PubBody))/binary, 0, Secret/binary>> = Body,
    [_D, P, Q, U] = mpis(Secret, 4),
    ?assert(P < Q),
    ?assertEqual(1, (P * U) rem Q),
    %% and the block imports, with a key OTP can sign with
    {ok, #{secret := {rsa, Priv2}, public := Pub}} = openpgp_crypto:import_keypair(Armored),
    {ok, Sig} = openpgp_detached_sig:sign(<<"d">>, {rsa, Priv2}, #{}),
    ?assertEqual(ok, openpgp_detached_sig:verify(<<"d">>, Sig, Pub)).

import_secret_key_block_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {ok, Armored, _} = openpgp_crypto:export_secret({ed25519, {Pub, Priv}}, #{userid => ?UID, signing_key => Priv}),
    ?assertEqual({ok, #{public => {ed25519, Pub}, secret => {ed25519, {Pub, Priv}}}},
                 openpgp_crypto:import_keypair(Armored)).

%% The MPI of an Ed25519 scalar with a leading zero octet is shorter.
import_ed25519_secret_with_leading_zero_test() ->
    {Pub, Priv} = leading_zero_ed25519_key(),
    {ok, Armored, _} = openpgp_crypto:export_secret({ed25519, {Pub, Priv}}, #{userid => ?UID}),
    ?assertMatch({ok, #{secret := {ed25519, {Pub, Priv}}}}, openpgp_crypto:import_keypair(Armored)).

leading_zero_ed25519_key() ->
    case crypto:generate_key(eddsa, ed25519) of
        {_, <<0, _/binary>>} = Key -> Key;
        _ -> leading_zero_ed25519_key()
    end.

created_in_milliseconds_test() ->
    {Pub, _} = crypto:generate_key(eddsa, ed25519),
    ?assertEqual(openpgp_crypto:fingerprint({ed25519, Pub}, 1700000000),
                 openpgp_crypto:fingerprint({ed25519, Pub}, 1700000000123)),
    ?assertEqual(openpgp_crypto:fingerprint({ed25519, Pub}, 1700000000),
                 openpgp_crypto:fingerprint({ed25519, Pub}, 1700000000123456)).

%% Helpers

created() ->
    openpgp_sig:subpacket(2, <<(erlang:system_time(second)):32>>).

doc_sig(Priv, Hashed) ->
    #{body := Body} = openpgp_sig:key_signature(ed25519, #{priv => Priv}, 16#00, <<"d">>, Hashed, []),
    openpgp_packets:encode([#{tag => 2, format => new, body => Body}]).

%% A document signature over "d" with another hash than key_signature/6 uses.
doc_sig(Alg, Priv, {HashId, Hash}, Hashed0) ->
    Hashed = iolist_to_binary(Hashed0),
    PkAlg = case Alg of rsa -> 1; ed25519 -> 22 end,
    Fields = <<4, 0, PkAlg, HashId, (byte_size(Hashed)):16, Hashed/binary>>,
    HashData = <<"d", Fields/binary, 4, 16#FF, (byte_size(Fields)):32>>,
    Digest = crypto:hash(Hash, HashData),
    Mpis =
        case Alg of
            rsa ->
                openpgp_mpi:encode_bin(crypto:sign(rsa, Hash, HashData, Priv));
            ed25519 ->
                <<R:32/binary, S:32/binary>> = crypto:sign(eddsa, none, Digest, [Priv, ed25519]),
                [openpgp_mpi:encode_bin(R), openpgp_mpi:encode_bin(S)]
        end,
    Body = iolist_to_binary([Fields, <<0:16>>, binary:part(Digest, 0, 2), Mpis]),
    openpgp_packets:encode([#{tag => 2, format => new, body => Body}]).

key() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {ok, Armored, _} = openpgp_crypto:export_public(
        {ed25519, Pub}, #{userid => ?UID, signing_key => Priv, created => erlang:system_time(second) - 1000}
    ),
    {ok, #{packets := [Prim, Uid, Cert]}} = gpg_keys:decode(Armored),
    #{prim => Prim, uid => Uid, cert => Cert, priv => Priv}.

key_created(#{body := <<4, Created:32, _/binary>>}) ->
    Created.

key_prefix(#{body := Body}) ->
    <<16#99, (byte_size(Body)):16, Body/binary>>.

uid_prefix(Prim, UserId) ->
    <<(key_prefix(Prim))/binary, 16#B4, (byte_size(UserId)):32, UserId/binary>>.

public_part(<<4, _:32, 1, Rest/binary>> = Body) ->
    [_, _] = mpis(Rest, 2),
    {ok, binary:part(Body, 0, 6 + mpis_size(Rest, 2))}.

mpis(_Bin, 0) ->
    [];
mpis(<<Bits:16, Rest/binary>>, K) ->
    Len = (Bits + 7) div 8,
    <<V:Len/binary, Tail/binary>> = Rest,
    [binary:decode_unsigned(V) | mpis(Tail, K - 1)].

mpis_size(_Bin, 0) ->
    0;
mpis_size(<<Bits:16, Rest/binary>>, K) ->
    Len = (Bits + 7) div 8,
    <<_:Len/binary, Tail/binary>> = Rest,
    2 + Len + mpis_size(Tail, K - 1).
