-module(openpgp_framing_tests).

-include_lib("eunit/include/eunit.hrl").

%% Packets

new_length_truncated_test_() ->
    [
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#C2, 200>>)),
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#C2, 255, 0, 0>>)),
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#C2>>)),
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#C2, 5, "abc">>))
    ].

old_length_truncated_test_() ->
    [
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#88>>)),
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#89, 0>>)),
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#8A, 0, 0, 0>>)),
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#88, 3, "ab">>))
    ].

two_and_five_octet_lengths_test() ->
    Body = binary:copy(<<"x">>, 300),
    ?assertEqual(
        {ok, [#{tag => 11, format => new, body => Body}]},
        openpgp_packets:decode(<<16#CB, 192, 108, Body/binary>>)
    ),
    ?assertEqual(
        {ok, [#{tag => 11, format => new, body => Body}]},
        openpgp_packets:decode(<<16#CB, 255, 300:32, Body/binary>>)
    ),
    ?assertEqual(
        {ok, [#{tag => 11, format => new, body => Body}]},
        openpgp_packets:decode(openpgp_packets:encode([#{tag => 11, format => new, body => Body}]))
    ).

reserved_tag_test_() ->
    [
        ?_assertEqual({error, {reserved_tag, 0}}, openpgp_packets:decode(<<16#C0, 1, 0>>)),
        ?_assertEqual({error, {reserved_tag, 0}}, openpgp_packets:decode(<<16#80, 1, 0>>))
    ].

partial_not_data_packet_test_() ->
    Chunk = binary:copy(<<"a">>, 512),
    [
        ?_assertMatch({error, _}, openpgp_packets:decode(<<16#C2, 16#E0, $a, 200>>)),
        ?_assertEqual(
            {error, {partial_length_not_allowed, 2}},
            openpgp_packets:decode(<<16#C2, 16#E9, Chunk/binary, 0>>)
        ),
        ?_assertEqual(
            {error, {partial_length_not_allowed, 6}},
            openpgp_packets:decode(<<16#C6, 16#E9, Chunk/binary, 0>>)
        )
    ].

partial_first_chunk_too_small_test() ->
    ?assertEqual(
        {error, {partial_chunk_too_small, 256}},
        openpgp_packets:decode(<<16#CB, 16#E8, (binary:copy(<<"a">>, 256))/binary, 0>>)
    ).

partial_data_packet_test() ->
    A = binary:copy(<<"a">>, 512),
    B = binary:copy(<<"b">>, 2),
    C = <<"cde">>,
    Bin = <<16#CB, 16#E9, A/binary, 16#E1, B/binary, 3, C/binary, 16#C2, 0>>,
    ?assertEqual(
        {ok, [
            #{tag => 11, format => new, body => <<A/binary, B/binary, C/binary>>},
            #{tag => 2, format => new, body => <<>>}
        ]},
        openpgp_packets:decode(Bin)
    ).

partial_chain_truncated_test_() ->
    A = binary:copy(<<"a">>, 512),
    [
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#CB, 16#E9, A/binary>>)),
        ?_assertEqual({error, truncated}, openpgp_packets:decode(<<16#CB, 16#E9, A/binary, 200>>)),
        ?_assertEqual(
            {error, truncated}, openpgp_packets:decode(<<16#CB, 16#E9, A/binary, 255, 0, 0>>)
        ),
        ?_assertEqual(
            {error, truncated}, openpgp_packets:decode(<<16#CB, 16#E9, A/binary, 4, "ab">>)
        )
    ].

%% MPI

mpi_test_() ->
    [
        ?_assertEqual({ok, {0, <<>>, <<"t">>}}, openpgp_mpi:decode_one(<<0, 0, "t">>)),
        ?_assertEqual({ok, {1, <<1>>, <<>>}}, openpgp_mpi:decode_one(<<0, 1, 1>>)),
        ?_assertEqual({ok, {9, <<1, 16#FF>>, <<>>}}, openpgp_mpi:decode_one(<<0, 9, 1, 16#FF>>)),
        ?_assertEqual({error, {bad_mpi_length, 1, 8}}, openpgp_mpi:decode_one(<<0, 1, 16#FF>>)),
        ?_assertEqual({ok, {9, <<0, 1>>, <<>>}}, openpgp_mpi:decode_one(<<0, 9, 0, 1>>)),
        ?_assertEqual({ok, {8, <<16#7F>>, <<>>}}, openpgp_mpi:decode_one(<<0, 8, 16#7F>>)),
        ?_assertEqual({error, truncated}, openpgp_mpi:decode_one(<<0, 9, 1>>)),
        ?_assertEqual({error, truncated}, openpgp_mpi:decode_one(<<0>>)),
        ?_assertEqual(
            {ok, {17, <<1, 0, 1>>, <<>>}},
            openpgp_mpi:decode_one(openpgp_mpi:encode_int(65537))
        )
    ].

%% Armor

armor_roundtrip_test() ->
    Data = crypto:strong_rand_bytes(100),
    Armored = openpgp_armor:encode(<<"PGP MESSAGE">>, [{<<"Comment">>, <<"hi">>}], Data),
    ?assertEqual(
        {ok, #{type => <<"PGP MESSAGE">>, headers => [{<<"Comment">>, <<"hi">>}], data => Data}},
        openpgp_armor:decode(Armored)
    ).

armor_missing_end_test() ->
    Armored = openpgp_armor:encode(<<"PGP MESSAGE">>, <<"abc">>),
    [Begin | _] = binary:split(Armored, <<"-----END">>),
    ?assertEqual({error, no_end_line}, openpgp_armor:decode(Begin)).

armor_wrong_end_type_test() ->
    Armored = openpgp_armor:encode(<<"PGP MESSAGE">>, <<"abc">>),
    Bad = binary:replace(Armored, <<"END PGP MESSAGE">>, <<"END PGP SIGNATURE">>),
    ?assertEqual({error, no_end_line}, openpgp_armor:decode(Bad)).

armor_trailing_whitespace_test() ->
    Armored = openpgp_armor:encode(<<"PGP MESSAGE">>, <<"abc">>),
    Ws1 = binary:replace(Armored, <<"MESSAGE-----\n">>, <<"MESSAGE----- \t\r\n">>, [global]),
    ?assertMatch({ok, #{type := <<"PGP MESSAGE">>, data := <<"abc">>}}, openpgp_armor:decode(Ws1)).

%% The CRC is optional, but checked when present.
armor_crc_test() ->
    Data = <<"some payload">>,
    Armored = openpgp_armor:encode(<<"PGP MESSAGE">>, Data),
    [Head, Crc, Tail] = binary:split(Armored, [<<"\n=">>, <<"\n-----END">>], [global]),
    BadCrc = <<"AAAA">>,
    ?assertNotEqual(BadCrc, Crc),
    Mismatch = <<Head/binary, "\n=", BadCrc/binary, "\n-----END", Tail/binary>>,
    Malformed = <<Head/binary, "\n=!!\n-----END", Tail/binary>>,
    NoCrc = <<Head/binary, "\n-----END", Tail/binary>>,
    ?assertMatch({ok, #{data := Data}}, openpgp_armor:decode(NoCrc)),
    ?assertMatch({error, {crc_mismatch, _, _}}, openpgp_armor:decode(Mismatch)),
    ?assertMatch({error, {bad_crc_base64, _}}, openpgp_armor:decode(Malformed)).

armor_encode_emits_crc_test() ->
    Data = <<"x">>,
    Crc = base64:encode(<<(openpgp_crc24:crc24(Data)):24>>),
    Armored = openpgp_armor:encode(<<"PGP MESSAGE">>, Data),
    ?assertNotEqual(nomatch, binary:match(Armored, <<"\n=", Crc/binary, "\n">>)).

armor_encode_bad_headers_test_() ->
    Enc = fun(H) -> openpgp_armor:encode(<<"PGP MESSAGE">>, [H], <<"x">>) end,
    [
        ?_assertError({bad_header, _}, Enc({<<"Comment">>, <<"a\nb">>})),
        ?_assertError({bad_header, _}, Enc({<<"Comment">>, <<"a\rb">>})),
        ?_assertError({bad_header, _}, Enc({<<"Com\nment">>, <<"a">>})),
        ?_assertError({bad_header, _}, Enc({<<"Com: ment">>, <<"a">>})),
        ?_assertError({bad_header, _}, Enc({<<>>, <<"a">>})),
        ?_assertError({bad_armor_type, _}, openpgp_armor:encode(<<"PGP\nMESSAGE">>, <<"x">>))
    ].

armor_decode_all_test() ->
    A = openpgp_armor:encode(<<"PGP PUBLIC KEY BLOCK">>, <<"one">>),
    B = openpgp_armor:encode(<<"PGP SIGNATURE">>, <<"two">>),
    Both = <<"junk\n", A/binary, "\nbetween\n", B/binary, "trailer\n">>,
    ?assertMatch(
        {ok, [
            #{type := <<"PGP PUBLIC KEY BLOCK">>, data := <<"one">>},
            #{type := <<"PGP SIGNATURE">>, data := <<"two">>}
        ]},
        openpgp_armor:decode_all(Both)
    ),
    ?assertMatch({ok, #{data := <<"one">>}}, openpgp_armor:decode(Both)),
    ?assertEqual({error, no_begin_line}, openpgp_armor:decode_all(<<"nothing">>)),
    [Truncated | _] = binary:split(B, <<"-----END">>),
    ?assertEqual({error, no_end_line}, openpgp_armor:decode_all(<<A/binary, Truncated/binary>>)).

%% gpg_keys

gpg_keys_armor_type_test_() ->
    Packets = [#{tag => 6, format => new, body => <<"key">>}],
    Data = openpgp_packets:encode(Packets),
    [
        ?_assertMatch(
            {ok, #{packets := Packets}}, gpg_keys:decode(gpg_keys:encode_public(Packets))
        ),
        ?_assertMatch(
            {ok, #{packets := Packets}}, gpg_keys:decode(gpg_keys:encode_private(Packets))
        ),
        ?_assertEqual(
            {error, {unexpected_armor_type, <<"PGP MESSAGE">>}},
            gpg_keys:decode(openpgp_armor:encode(<<"PGP MESSAGE">>, Data))
        )
    ].

gpg_keys_is_armored_test_() ->
    Packets = [#{tag => 6, format => new, body => <<"key">>}],
    Armored = gpg_keys:encode_public(Packets),
    [
        ?_assertMatch({ok, #{packets := Packets}}, gpg_keys:decode(<<" \r\n\n", Armored/binary>>)),
        ?_assertEqual(
            {error, {not_a_packet, $x}}, gpg_keys:decode(<<"x", Armored/binary>>)
        ),
        ?_assertMatch(
            {ok, #{armor := undefined, packets := Packets}},
            gpg_keys:decode(openpgp_packets:encode(Packets))
        )
    ].

gpg_keys_truncated_test_() ->
    [
        ?_assertEqual({error, truncated}, gpg_keys:decode(<<16#C2, 200>>)),
        ?_assertEqual({error, truncated}, gpg_keys:decode(<<16#C2, 255, 0, 0>>)),
        ?_assertMatch({error, _}, gpg_keys:decode(<<16#C2, 16#E0, $a, 200>>)),
        ?_assertEqual({error, truncated}, gpg_keys:decode_packets(<<16#C2, 200>>)),
        ?_assertEqual(
            {error, truncated},
            gpg_keys:decode(openpgp_armor:encode(<<"PGP PUBLIC KEY BLOCK">>, <<16#C6, 200>>))
        )
    ].

%% Dash escaping

dash_unescape_test_() ->
    [
        ?_assertEqual(
            {ok, <<"-a\nFrom x\nb">>}, openpgp_text:dash_unescape(<<"- -a\n- From x\nb">>)
        ),
        ?_assertEqual({ok, <<"x">>}, openpgp_text:dash_unescape(<<"- x">>)),
        ?_assertEqual(
            {error, {bad_dash_escape, <<"-a">>}}, openpgp_text:dash_unescape(<<"ok\n-a\nmore">>)
        ),
        ?_assertEqual({error, {bad_dash_escape, <<"-">>}}, openpgp_text:dash_unescape(<<"-">>)),
        ?_assertEqual(
            {ok, <<"-x\n">>}, openpgp_text:dash_unescape(openpgp_text:dash_escape(<<"-x\n">>))
        )
    ].

%% Cleartext

ed_key() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    {{ed25519, Pub}, {ed25519, Priv}}.

cleartext_hashes_test_() ->
    {Pub, Priv} = ed_key(),
    [
        {atom_to_list(H), fun() ->
            {ok, Clear} = openpgp_cleartext:sign(<<"hello\n-dash\n">>, Priv, #{hash => H}),
            ?assertNotEqual(nomatch, binary:match(Clear, <<"\nHash: ", Name/binary, "\n">>)),
            ?assertMatch({ok, #{hashes := [Name]}}, openpgp_cleartext:parse(Clear)),
            ?assertEqual(ok, openpgp_cleartext:verify(Clear, Pub))
        end}
     || {H, Name} <- [{sha256, <<"SHA256">>}, {sha384, <<"SHA384">>}, {sha512, <<"SHA512">>}]
    ].

cleartext_unsupported_hash_test() ->
    {_Pub, Priv} = ed_key(),
    ?assertMatch({error, _}, openpgp_cleartext:sign(<<"x">>, Priv, #{hash => md5})).

cleartext_tampered_text_test() ->
    {Pub, Priv} = ed_key(),
    {ok, Clear} = openpgp_cleartext:sign(<<"hello\nworld\n">>, Priv, #{}),
    Bad = binary:replace(Clear, <<"world">>, <<"World">>),
    ?assertMatch({error, _}, openpgp_cleartext:verify(Bad, Pub)).

cleartext_bad_dash_escape_test() ->
    {Pub, Priv} = ed_key(),
    {ok, Clear} = openpgp_cleartext:sign(<<"-dash\n">>, Priv, #{}),
    Bad = binary:replace(Clear, <<"- -dash">>, <<"-dash">>),
    ?assertEqual({error, {bad_dash_escape, <<"-dash">>}}, openpgp_cleartext:verify(Bad, Pub)).

cleartext_hash_header_test_() ->
    {Pub, Priv} = ed_key(),
    {ok, Clear} = openpgp_cleartext:sign(<<"hello\n">>, Priv, #{hash => sha256}),
    Hdr = fun(New) -> binary:replace(Clear, <<"Hash: SHA256\n">>, New) end,
    [
        ?_assertEqual(ok, openpgp_cleartext:verify(Hdr(<<"Hash: SHA512, SHA256\n">>), Pub)),
        ?_assertEqual(ok, openpgp_cleartext:verify(Hdr(<<"Hash: SHA512\nHash: SHA256\n">>), Pub)),
        ?_assertEqual(ok, openpgp_cleartext:verify(Hdr(<<"Hash: SHA256\r\n">>), Pub)),
        ?_assertEqual(ok, openpgp_cleartext:verify(Hdr(<<>>), Pub)),
        ?_assertMatch({ok, #{hashes := undefined}}, openpgp_cleartext:parse(Hdr(<<>>))),
        ?_assertEqual(
            {error, {hash_not_in_header, 8}},
            openpgp_cleartext:verify(Hdr(<<"Hash: SHA512\n">>), Pub)
        ),
        ?_assertEqual(
            {error, {hash_not_in_header, 8}},
            openpgp_cleartext:verify(Hdr(<<"Hash: SHA1,SHA3-256\n">>), Pub)
        ),
        ?_assertEqual(
            {error, {unknown_hash, <<"sha256">>}},
            openpgp_cleartext:verify(Hdr(<<"Hash: sha256\n">>), Pub)
        ),
        ?_assertEqual(
            {error, {unknown_hash, <<"SHA999">>}},
            openpgp_cleartext:verify(Hdr(<<"Hash: SHA256, SHA999\n">>), Pub)
        ),
        ?_assertEqual(
            {error, {bad_armor_header, <<"Comment: hi">>}},
            openpgp_cleartext:verify(Hdr(<<"Hash: SHA256\nComment: hi\n">>), Pub)
        ),
        ?_assertEqual(
            {error, {bad_armor_header, <<"Hash:SHA256">>}},
            openpgp_cleartext:verify(Hdr(<<"Hash:SHA256\n">>), Pub)
        )
    ].

%% Two signatures over the same text, one SHA256 and one SHA512, in one
%% signature block.
two_sig_clear() ->
    {Pub1, Priv1} = ed_key(),
    {Pub2, Priv2} = ed_key(),
    Text = <<"hello\n">>,
    {ok, C1} = openpgp_cleartext:sign(Text, Priv1, #{hash => sha256}),
    {ok, C2} = openpgp_cleartext:sign(Text, Priv2, #{hash => sha512}),
    {ok, #{signature := S1}} = openpgp_cleartext:parse(C1),
    {ok, #{signature := S2}} = openpgp_cleartext:parse(C2),
    {ok, #{data := D1}} = openpgp_armor:decode(S1),
    {ok, #{data := D2}} = openpgp_armor:decode(S2),
    Sig = openpgp_armor:encode(<<"PGP SIGNATURE">>, <<D1/binary, D2/binary>>),
    Clear = iolist_to_binary([
        <<"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256,SHA512\n\n">>, Text, Sig
    ]),
    {Clear, Pub1, Pub2}.

cleartext_multiple_signatures_hash_test() ->
    {Clear, _Pub1, Pub2} = two_sig_clear(),
    Only256 = binary:replace(Clear, <<"Hash: SHA256,SHA512">>, <<"Hash: SHA256">>),
    ?assertEqual({error, {hash_not_in_header, 10}}, openpgp_cleartext:verify(Only256, Pub2)),
    Only512 = binary:replace(Clear, <<"Hash: SHA256,SHA512">>, <<"Hash: SHA512">>),
    ?assertEqual({error, {hash_not_in_header, 8}}, openpgp_cleartext:verify(Only512, Pub2)).

cleartext_multiple_signatures_verify_test() ->
    {Clear, Pub1, Pub2} = two_sig_clear(),
    ?assertEqual(ok, openpgp_cleartext:verify(Clear, Pub1)),
    ?assertEqual(ok, openpgp_cleartext:verify(Clear, Pub2)),
    {Pub3, _} = ed_key(),
    ?assertMatch({error, _}, openpgp_cleartext:verify(Clear, Pub3)).
