%%% @doc OpenPGP detached signature sign/verify (v4 Signature packet).
%%%
%%% Interop goal:
%%% - Verify a detached signature produced by `gpg --detach-sign`
%%% - Produce a detached signature that `gpg --verify` accepts
%%%
%%% This module signs "binary document" (signature type 0x00): bytes are used as-is.
%%% (No canonical text conversion.)
-module(openpgp_detached_sig).

-include_lib("public_key/include/public_key.hrl").

-export([
    sign/3,
    sign_key/3,
    verify/3,
    verify_key/3,
    parse_signature/1
]).

-type pubkey() :: {rsa, [binary()]} | {ed25519, binary()}.
-type privkey() :: {rsa, [binary()]} | {ed25519, binary()}.

-type sig_info() :: #{
    version := 4,
    sig_type := non_neg_integer(),
    pk_alg := non_neg_integer(),
    hash_alg := non_neg_integer(),
    hashed_sub := binary(),
    unhashed_sub := binary(),
    hash16 := binary(),
    mpis := [binary()]
}.

%% @doc Create a detached signature for Data.
%%
%% `Key` must be:
%% - `{rsa, Priv}` where Priv is from `crypto:generate_key(rsa, ...)`
%% - `{ed25519, Priv32}` where Priv32 is 32 bytes
%%
%% Options:
%% - `#{hash => sha256|sha512, created => UnixSeconds, issuer_fpr => Fingerprint20Bin, sig_type => 16#00|16#01}`
%% - `#{armor => true|false}` (default true)
-spec sign(binary() | iodata(), privkey(), map()) -> {ok, binary()} | {error, term()}.
sign(Data0, Key, Opts) ->
    SigType = maps:get(sig_type, Opts, 16#00),
    Data1 = iolist_to_binary(Data0),
    Data =
        case SigType of
            16#00 -> Data1;
            16#01 -> openpgp_text:canonicalize_text(Data1);
            _ -> return_error({unsupported_sig_type, SigType})
        end,
    Hash = maps:get(hash, Opts, sha512),
    {HashAlgId, HashAlgCrypto} = hash_alg(Hash),
    {PkAlgId, Alg} =
        case Key of
            {rsa, _Priv} -> {1, rsa};
            {ed25519, _Priv32} -> {22, ed25519};
            _ -> return_error({unsupported_key, Key})
        end,
    Created = maps:get(created, Opts, erlang:system_time(second)),
    HashedSub = iolist_to_binary([subpacket(2, <<Created:32/big-unsigned>>) | maybe_issuer_fpr(Opts)]),
    UnhashedSub = iolist_to_binary(maybe_issuer_keyid(Opts)),

    SigHashedFields =
        iolist_to_binary([
            <<4:8, SigType:8, PkAlgId:8, HashAlgId:8>>,
            <<(byte_size(HashedSub)):16/big-unsigned>>,
            HashedSub
        ]),
    TrailerLen = byte_size(SigHashedFields),
    Trailer = <<4:8, 16#FF:8, TrailerLen:32/big-unsigned>>,
    HashData = iolist_to_binary([Data, SigHashedFields, Trailer]),
    Digest = crypto:hash(HashAlgCrypto, HashData),
    Hash16 = binary:part(Digest, 0, 2),

    Mpis =
        case {Alg, Key} of
            {rsa, {rsa, Priv}} ->
                Sig = crypto:sign(rsa, HashAlgCrypto, HashData, Priv),
                [openpgp_mpi:encode_bin(Sig)];
            {ed25519, {ed25519, Priv32}} when is_binary(Priv32), byte_size(Priv32) =:= 32 ->
                Sig64 = crypto:sign(eddsa, none, Digest, [Priv32, ed25519]),
                <<R:32/binary, S:32/binary>> = Sig64,
                [openpgp_mpi:encode_bin(R), openpgp_mpi:encode_bin(S)]
        end,

    Body =
        iolist_to_binary([
            SigHashedFields,
            <<(byte_size(UnhashedSub)):16/big-unsigned>>,
            UnhashedSub,
            Hash16,
            Mpis
        ]),
    Bin = openpgp_packets:encode([#{tag => 2, format => new, body => Body}]),
    case maps:get(armor, Opts, true) of
        true -> {ok, openpgp_armor:encode(<<"PGP SIGNATURE">>, Bin)};
        false -> {ok, Bin};
        Other -> return_error({bad_armor_opt, Other})
    end.

%% @doc Like `sign/3`, but also accepts common `public_key` key formats:
%% - `#'RSAPrivateKey'{...}`
%% - `#'ECPrivateKey'{...}` for Ed25519
%% - raw tuple `{'ECPrivateKey',...}` for Ed25519 (OTP variant)
-spec sign_key(binary() | iodata(), term(), map()) -> {ok, binary()} | {error, term()}.
sign_key(Data, KeyAny, Opts) ->
    case normalize_priv_key(KeyAny) of
        {ok, Key} -> sign(Data, Key, Opts);
        {error, _} = Err -> Err
    end.

%% @doc Verify a detached signature for Data with a public key in OTP crypto-format.
%%
%% `PubKey`:
%% - `{rsa, [E,N]}`
%% - `{ed25519, Pub32}`
-spec verify(binary() | iodata(), binary() | iodata(), pubkey()) -> ok | {error, term()}.
verify(Data0, Sig0, PubKey) ->
    try
        Data = iolist_to_binary(Data0),
        SigBin =
            case is_armored(iolist_to_binary(Sig0)) of
                true ->
                    case openpgp_armor:decode(Sig0) of
                        {ok, #{data := D}} -> D;
                        {error, _} -> throw(malformed_signature)
                    end;
                false ->
                    iolist_to_binary(Sig0)
            end,
        case openpgp_packets:decode(SigBin) of
            {ok, [#{tag := 2, body := Body} | _]} ->
                case parse_signature_body(Body) of
                    {ok, Info} ->
                        verify_with_info(Data, Info, PubKey);
                    {error, _} ->
                        malformed_sig()
                end;
            {ok, _Other} ->
                malformed_sig();
            {error, _} ->
                malformed_sig()
        end
    catch
        throw:malformed_signature ->
            malformed_sig();
        error:{bad_ed25519_public, _} ->
            malformed_sig();
        error:{bad_len, _} ->
            malformed_sig();
        error:{badarg, _} ->
            malformed_sig();
        error:badarg ->
            malformed_sig();
        error:{case_clause, _} ->
            malformed_sig()
    end.

%% @doc Like `verify/3`, but also accepts common `public_key` key formats:
%% - `#'RSAPublicKey'{...}` or `#'RSAPrivateKey'{...}` (public fields used)
%% - `{#'ECPoint'{point=Pub}, {namedCurve,Oid}}` for Ed25519
%% - raw tuple `{'ECPrivateKey',...}` for Ed25519 (public field used)
-spec verify_key(binary() | iodata(), binary() | iodata(), term()) -> ok | {error, term()}.
verify_key(Data, Sig, KeyAny) ->
    case normalize_pub_key(KeyAny) of
        {ok, PubKey} -> verify(Data, Sig, PubKey);
        {error, _} = Err -> Err
    end.

%% @doc Parse a detached signature (returns decoded signature fields).
-spec parse_signature(binary() | iodata()) -> {ok, sig_info()} | {error, term()}.
parse_signature(Sig0) ->
    try
        SigBin =
            case is_armored(iolist_to_binary(Sig0)) of
                true ->
                    case openpgp_armor:decode(Sig0) of
                        {ok, #{data := D}} -> D;
                        {error, _} -> throw(malformed_signature)
                    end;
                false ->
                    iolist_to_binary(Sig0)
            end,
        case openpgp_packets:decode(SigBin) of
            {ok, [#{tag := 2, body := Body} | _]} ->
                case parse_signature_body(Body) of
                    {ok, _} = Ok -> Ok;
                    {error, _} -> malformed_sig()
                end;
            _ ->
                malformed_sig()
        end
    catch
        throw:malformed_signature ->
            malformed_sig()
    end.

%% Internal

verify_with_info(Data, Info, PubKey) ->
    HashedSub = maps:get(hashed_sub, Info),
    _UnhashedSub = maps:get(unhashed_sub, Info),
    PkAlgId = maps:get(pk_alg, Info),
    HashAlgId = maps:get(hash_alg, Info),
    SigType = maps:get(sig_type, Info),
    Hash16 = maps:get(hash16, Info),
    MpiList = maps:get(mpis, Info),

    Data2 =
        case SigType of
            16#00 -> Data;
            16#01 -> openpgp_text:canonicalize_text(Data);
            _ -> return_error({unsupported_sig_type, SigType})
        end,
    case Data2 of
        {error, _} = E0 ->
            E0;
        _ ->
            SigHashedFields =
                iolist_to_binary([
                    <<4:8, SigType:8, PkAlgId:8, HashAlgId:8>>,
                    <<(byte_size(HashedSub)):16/big-unsigned>>,
                    HashedSub
                ]),
            TrailerLen = byte_size(SigHashedFields),
            Trailer = <<4:8, 16#FF:8, TrailerLen:32/big-unsigned>>,
            HashData = iolist_to_binary([Data2, SigHashedFields, Trailer]),
            case hash_alg_id(HashAlgId) of
                {error, _} = E1 ->
                    E1;
                {HashCrypto, _Name} ->
                    Digest = crypto:hash(HashCrypto, HashData),
                    case binary:part(Digest, 0, 2) =:= Hash16 of
                        false ->
                            bad_sig();
                        true ->
                            case {PkAlgId, PubKey, MpiList} of
                                {1, {rsa, [E, N]}, [SigMpi]} ->
                                    case openpgp_mpi:decode_one(SigMpi) of
                                        {ok, {_Bits, SigBin, <<>>}} ->
                                            case crypto:verify(rsa, HashCrypto, HashData, SigBin, [E, N]) of
                                                true -> ok;
                                                false -> bad_sig()
                                            end;
                                        _ ->
                                            malformed_sig()
                                    end;
                                {22, {ed25519, Pub32}, [RMpi, SMpi]}
                                  when is_binary(Pub32), byte_size(Pub32) =:= 32 ->
                                    {ok, {_RB, R, <<>>}} = openpgp_mpi:decode_one(RMpi),
                                    {ok, {_SB, S, <<>>}} = openpgp_mpi:decode_one(SMpi),
                                    Sig = <<(pad32(R))/binary, (pad32(S))/binary>>,
                                    case crypto:verify(eddsa, none, Digest, Sig, [Pub32, ed25519]) of
                                        true -> ok;
                                        false -> bad_sig()
                                    end;
                                _ ->
                                    {error, {unsupported_signature_alg, PkAlgId, PubKey, length(MpiList)}}
                            end
                    end
            end
    end.

parse_signature_body(
    <<4:8, SigType:8, PkAlgId:8, HashAlgId:8, HashedLen:16/big-unsigned, Hashed:HashedLen/binary,
      UnhashedLen:16/big-unsigned, Unhashed:UnhashedLen/binary, Hash16:2/binary, Rest/binary>>
) ->
    case decode_mpis(Rest, []) of
        {ok, Mpis} ->
            {ok,
                #{
                    version => 4,
                    sig_type => SigType,
                    pk_alg => PkAlgId,
                    hash_alg => HashAlgId,
                    hashed_sub => Hashed,
                    unhashed_sub => Unhashed,
                    hash16 => Hash16,
                    mpis => Mpis
                }};
        {error, _} = Err ->
            Err
    end;
parse_signature_body(_) ->
    {error, bad_signature_packet}.

decode_mpis(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_mpis(Bin, Acc) ->
    case openpgp_mpi:decode_one(Bin) of
        {ok, {Bits, Val, Tail}} ->
            % Preserve the *original* MPI encoding. Re-encoding may drop leading zeros
            % and break RSA signature verification.
            Mpi = <<Bits:16/big-unsigned, Val/binary>>,
            decode_mpis(Tail, [Mpi | Acc]);
        {error, _} = Err ->
            Err
    end.

subpacket(Type, Data) ->
    Len = 1 + byte_size(Data),
    <<Len:8, Type:8, Data/binary>>.

maybe_issuer_fpr(Opts) ->
    case maps:find(issuer_fpr, Opts) of
        error -> [];
        {ok, Fpr} when is_binary(Fpr), byte_size(Fpr) =:= 20 ->
            [subpacket(33, <<4:8, Fpr/binary>>)];
        {ok, Other} ->
            error({bad_issuer_fpr, Other})
    end.

maybe_issuer_keyid(Opts) ->
    case maps:find(issuer_fpr, Opts) of
        error ->
            [];
        {ok, Fpr} when is_binary(Fpr), byte_size(Fpr) =:= 20 ->
            KeyId = openpgp_fingerprint:keyid_from_fingerprint(Fpr),
            [subpacket(16, KeyId)];
        {ok, _Other} ->
            []
    end.

hash_alg(sha256) -> {8, sha256};
hash_alg(sha512) -> {10, sha512}.

hash_alg_id(8) -> {sha256, <<"SHA256">>};
hash_alg_id(10) -> {sha512, <<"SHA512">>};
hash_alg_id(Other) -> return_error({unsupported_hash_alg, Other}).

pad32(Bin) when is_binary(Bin), byte_size(Bin) =:= 32 -> Bin;
pad32(Bin) when is_binary(Bin), byte_size(Bin) < 32 ->
    Pad = 32 - byte_size(Bin),
    <<0:Pad/unit:8, Bin/binary>>;
pad32(Bin) when is_binary(Bin), byte_size(Bin) > 32 ->
    % MPI decode may yield leading zeros stripped; reject if too long.
    error({bad_len, byte_size(Bin)}).

is_armored(Bin) ->
    case binary:match(Bin, <<"-----BEGIN PGP SIGNATURE-----">>) of
        nomatch -> false;
        _ -> true
    end.

return_error(R) -> {error, R}.

malformed_sig() ->
    {error, #{reason => malformed_signature, message => <<"malformed signature">>}}.

bad_sig() ->
    {error, #{reason => bad_signature, message => <<"bad signature">>}}.

%% Key normalization (public_key record/tuple -> our crypto formats)

normalize_pub_key({rsa, [E, N]} = K) when is_binary(E), is_binary(N) ->
    {ok, K};
normalize_pub_key({ed25519, Pub32} = K) when is_binary(Pub32), byte_size(Pub32) =:= 32 ->
    {ok, K};
normalize_pub_key(#'RSAPublicKey'{modulus = N, publicExponent = E}) ->
    {ok, {rsa, [bin_u(E), bin_u(N)]}};
normalize_pub_key(#'RSAPrivateKey'{modulus = N, publicExponent = E}) ->
    {ok, {rsa, [bin_u(E), bin_u(N)]}};
normalize_pub_key({#'ECPoint'{point = Pub0}, {namedCurve, {1,3,101,112}}}) ->
    {ok, {ed25519, ed25519_pub32(Pub0)}};
normalize_pub_key({'ECPrivateKey', _Ver, _Priv, {namedCurve, {1,3,101,112}}, PubField}) ->
    {ok, {ed25519, ed25519_pub32(PubField)}};
normalize_pub_key({'ECPrivateKey', _Ver, _Priv, {namedCurve, {1,3,101,112}}, PubField, _Attrs}) ->
    {ok, {ed25519, ed25519_pub32(PubField)}};
normalize_pub_key(Other) ->
    {error, {unsupported_public_key_format, Other}}.

normalize_priv_key({rsa, Priv} = K) when is_list(Priv) ->
    {ok, K};
normalize_priv_key({ed25519, Priv32} = K) when is_binary(Priv32), byte_size(Priv32) =:= 32 ->
    {ok, K};
normalize_priv_key(#'RSAPrivateKey'{} = R) ->
    try
        PrivCrypto = [
            bin_u(R#'RSAPrivateKey'.publicExponent),
            bin_u(R#'RSAPrivateKey'.modulus),
            bin_u(R#'RSAPrivateKey'.privateExponent),
            bin_u(R#'RSAPrivateKey'.prime1),
            bin_u(R#'RSAPrivateKey'.prime2),
            bin_u(R#'RSAPrivateKey'.exponent1),
            bin_u(R#'RSAPrivateKey'.exponent2),
            bin_u(R#'RSAPrivateKey'.coefficient)
        ],
        {ok, {rsa, PrivCrypto}}
    catch _:_ ->
        {error, incomplete_rsa_private}
    end;
normalize_priv_key(#'ECPrivateKey'{parameters = {namedCurve, {1,3,101,112}}, privateKey = Priv0}) ->
    case ed25519_priv32(Priv0) of
        {ok, Priv32} -> {ok, {ed25519, Priv32}};
        {error, _} = Err -> Err
    end;
normalize_priv_key({'ECPrivateKey', _Ver, PrivField, {namedCurve, {1,3,101,112}}, _PubField}) ->
    case ed25519_priv32(PrivField) of
        {ok, Priv32} -> {ok, {ed25519, Priv32}};
        {error, _} = Err -> Err
    end;
normalize_priv_key(Other) ->
    {error, {unsupported_private_key_format, Other}}.

bin_u(I) when is_integer(I), I >= 0 -> binary:encode_unsigned(I);
bin_u(B) when is_binary(B) -> B.

ed25519_pub32(Pub) when is_binary(Pub), byte_size(Pub) =:= 32 ->
    Pub;
ed25519_pub32({0, Pub}) when is_binary(Pub), byte_size(Pub) =:= 32 ->
    Pub;
ed25519_pub32(Other) ->
    error({bad_ed25519_public, Other}).

ed25519_priv32(Priv) when is_binary(Priv), byte_size(Priv) =:= 32 ->
    {ok, Priv};
ed25519_priv32(Bin65) when is_binary(Bin65), byte_size(Bin65) =:= 65 ->
    <<_Tag:8, Priv32:32/binary, _Pub:32/binary>> = Bin65,
    {ok, Priv32};
ed25519_priv32(Bin64) when is_binary(Bin64), byte_size(Bin64) =:= 64 ->
    <<Priv32:32/binary, _Pub:32/binary>> = Bin64,
    {ok, Priv32};
ed25519_priv32(I) when is_integer(I), I >= 0 ->
    Bin = binary:encode_unsigned(I),
    case byte_size(Bin) =< 32 of
        true ->
            Pad = 32 - byte_size(Bin),
            {ok, <<0:Pad/unit:8, Bin/binary>>};
        false ->
            {error, bad_ed25519_private_size}
    end;
ed25519_priv32(Other) ->
    {error, {bad_ed25519_private, Other}}.


