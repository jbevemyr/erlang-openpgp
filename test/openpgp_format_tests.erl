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


