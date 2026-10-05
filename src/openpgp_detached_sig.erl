%%% @doc OpenPGP detached signature sign/verify (v4 Signature packet).
%%%
%%% Interop goal:
%%% - Verify a detached signature produced by `gpg --detach-sign`
%%% - Produce a detached signature that `gpg --verify` accepts
%%%
%%% This module signs "binary document" (signature type 0x00) by default;
%%% "canonical text document" (0x01) converts line endings to CRLF first.
%%%
%%% The key-signature verification (`verify_key_signature/4`) is shared with
%%% the key block import in `openpgp_crypto`: certifications and subkey
%%% bindings are v4 signatures over a key-derived prefix instead of a document.
-module(openpgp_detached_sig).

-include_lib("public_key/include/public_key.hrl").

-export([
    sign/3,
    sign_key/3,
    verify/3,
    verify/4,
    verify_key/3,
    verify_key/4,
    verify_key_signature/4,
    parse_signature/1,
    sig_subpackets/1,
    sig_subpacket/2,
    named_issuers/2,
    is_issuer/2,
    hash_alg/1
]).

-type pubkey() :: {rsa, [binary()]} | {ed25519, binary()}.
-type privkey() :: {rsa, [binary()]} | {ed25519, binary()}.

%% Verification options. All are checks on top of the cryptographic
%% verification; each one is skipped when the option is absent.
%% - sig_type: the signature type the caller expects (0x00 or 0x01); a
%%   signature of another type is rejected instead of being verified under
%%   its own canonicalization rules.
%% - issuer_fpr: when the signature names an issuer (subpacket 33 or 16) it
%%   must be this key.
%% - key_created: the signature must not predate the key.
%% - now: reference time for creation and expiration checks (default: the
%%   system clock).
-type verify_opts() :: #{
    sig_type => 16#00 | 16#01,
    issuer_fpr => binary(),
    key_created => non_neg_integer(),
    now => non_neg_integer()
}.

%% Tolerated clock skew for "created in the future".
-define(SKEW, 300).

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
%% - `#{hash => sha256|sha384|sha512, created => UnixSeconds, issuer_fpr => Fingerprint20Bin, sig_type => 16#00|16#01}`
%% - `#{expires => Seconds}` signature lifetime (subpacket 3)
%% - `#{armor => true|false}` (default true)
-spec sign(binary() | iodata(), privkey(), map()) -> {ok, binary()} | {error, term()}.
sign(Data0, Key, Opts) ->
    try
        SigType = maps:get(sig_type, Opts, 16#00),
        Data1 = iolist_to_binary(Data0),
        Data =
            case SigType of
                16#00 -> Data1;
                16#01 -> openpgp_text:canonicalize_text(Data1);
                _ -> throw({unsupported_sig_type, SigType})
            end,
        {HashAlgId, HashAlgCrypto} =
            case hash_alg(maps:get(hash, Opts, sha512)) of
                {error, R0} -> throw(R0);
                H -> H
            end,
        {PkAlgId, Alg} =
            case Key of
                {rsa, _Priv} -> {1, rsa};
                {ed25519, P32} when is_binary(P32), byte_size(P32) =:= 32 -> {22, ed25519};
                _ -> throw({unsupported_key, Key})
            end,
        Created = maps:get(created, Opts, erlang:system_time(second)),
        HashedSub = iolist_to_binary(
            [subpacket(2, <<Created:32/big-unsigned>>)] ++
                maybe_expiration(Opts) ++
                maybe_issuer_fpr(Opts)
        ),
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
                {ed25519, {ed25519, Priv32}} ->
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
            Other -> {error, {bad_armor_opt, Other}}
        end
    catch
        throw:Reason ->
            {error, Reason}
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
    verify(Data0, Sig0, PubKey, #{}).

-spec verify(binary() | iodata(), binary() | iodata(), pubkey(), verify_opts()) ->
    ok | {error, term()}.
verify(Data0, Sig0, PubKey, Opts) ->
    guarded(fun() ->
        Data = iolist_to_binary(Data0),
        case openpgp_packets:decode(unarmor(Sig0)) of
            {ok, [#{tag := 2, body := Body} | _]} ->
                case parse_signature_body(Body) of
                    {ok, Info} -> verify_with_info(Data, Info, PubKey, Opts);
                    {error, _} -> malformed_sig()
                end;
            _ ->
                malformed_sig()
        end
    end).

%% @doc Like `verify/3`, but also accepts common `public_key` key formats:
%% - `#'RSAPublicKey'{...}` or `#'RSAPrivateKey'{...}` (public fields used)
%% - `{#'ECPoint'{point=Pub}, {namedCurve,Oid}}` for Ed25519
%% - raw tuple `{'ECPrivateKey',...}` for Ed25519 (public field used)
-spec verify_key(binary() | iodata(), binary() | iodata(), term()) -> ok | {error, term()}.
verify_key(Data, Sig, KeyAny) ->
    verify_key(Data, Sig, KeyAny, #{}).

-spec verify_key(binary() | iodata(), binary() | iodata(), term(), verify_opts()) ->
    ok | {error, term()}.
verify_key(Data, Sig, KeyAny, Opts) ->
    case normalize_pub_key(KeyAny) of
        {ok, PubKey} -> verify(Data, Sig, PubKey, Opts);
        {error, _} = Err -> Err
    end.

%% @doc Verify a v4 key signature (certification, subkey binding, backsig).
%%
%% `Prefix` is the key-derived data the signature is computed over: the
%% 0x99-framed public key body, followed by the 0xB4-framed User ID for
%% certifications or the 0x99-framed subkey body for bindings. `SigBody` is
%% the Signature packet body. `AllowedTypes` lists the signature types the
%% caller accepts. Returns the parsed signature on success, so the caller can
%% read its subpackets.
-spec verify_key_signature(binary(), binary(), pubkey(), [non_neg_integer()]) ->
    {ok, sig_info()} | {error, term()}.
verify_key_signature(Prefix, SigBody, PubKey, AllowedTypes) ->
    guarded(fun() ->
        case parse_signature_body(SigBody) of
            {ok, #{sig_type := SigType} = Info} ->
                case lists:member(SigType, AllowedTypes) of
                    false ->
                        {error, {unexpected_sig_type, SigType}};
                    true ->
                        case verify_hash_and_sig(Prefix, Info, PubKey) of
                            ok -> {ok, Info};
                            {error, _} = Err -> Err
                        end
                end;
            {error, _} ->
                malformed_sig()
        end
    end).

%% @doc Parse a detached signature (returns decoded signature fields).
-spec parse_signature(binary() | iodata()) -> {ok, sig_info()} | {error, term()}.
parse_signature(Sig0) ->
    guarded(fun() ->
        case openpgp_packets:decode(unarmor(Sig0)) of
            {ok, [#{tag := 2, body := Body} | _]} ->
                case parse_signature_body(Body) of
                    {ok, _} = Ok -> Ok;
                    {error, _} -> malformed_sig()
                end;
            _ ->
                malformed_sig()
        end
    end).

%% @doc Decode a signature subpacket area into `[{Type, Data}]`.
%%
%% Handles the 1-, 2- and 5-octet length forms (RFC 4880 5.2.3.1) and masks
%% the critical bit off the type. A truncated area yields what was decoded
%% before the truncation.
-spec sig_subpackets(binary()) -> [{non_neg_integer(), binary()}].
sig_subpackets(Bin) ->
    sig_subpackets(Bin, []).

sig_subpackets(<<>>, Acc) ->
    lists:reverse(Acc);
sig_subpackets(Bin, Acc) ->
    case subpacket_len(Bin) of
        {ok, Len, <<T:8, Rest/binary>>} when Len >= 1 ->
            DataLen = Len - 1,
            case Rest of
                <<Data:DataLen/binary, Tail/binary>> ->
                    sig_subpackets(Tail, [{T band 16#7F, Data} | Acc]);
                _ ->
                    lists:reverse(Acc)
            end;
        _ ->
            lists:reverse(Acc)
    end.

%% @doc The data of the first subpacket of the given type, if any.
-spec sig_subpacket(non_neg_integer(), binary()) -> {ok, binary()} | error.
sig_subpacket(Type, Bin) ->
    case lists:keyfind(Type, 1, sig_subpackets(Bin)) of
        {Type, Data} -> {ok, Data};
        false -> error
    end.

subpacket_len(<<First:8, Rest/binary>>) when First < 192 ->
    {ok, First, Rest};
subpacket_len(<<First:8, Second:8, Rest/binary>>) when First >= 192, First < 255 ->
    {ok, ((First - 192) bsl 8) + Second + 192, Rest};
subpacket_len(<<255:8, Len:32/big-unsigned, Rest/binary>>) ->
    {ok, Len, Rest};
subpacket_len(_) ->
    error.

%% Internal

%% Malformed input surfaces as a malformed-signature error rather than a
%% crash, whatever shape it takes.
guarded(F) ->
    try
        F()
    catch
        throw:malformed_signature -> malformed_sig();
        error:{bad_ed25519_public, _} -> malformed_sig();
        error:{bad_len, _} -> malformed_sig();
        error:{badarg, _} -> malformed_sig();
        error:badarg -> malformed_sig();
        error:{badmatch, _} -> malformed_sig();
        error:{case_clause, _} -> malformed_sig();
        error:function_clause -> malformed_sig()
    end.

verify_with_info(Data, Info, PubKey, Opts) ->
    SigType = maps:get(sig_type, Info),
    case check_sig_type(SigType, Opts) of
        {error, _} = E0 ->
            E0;
        ok ->
            case check_subpackets(Info, Opts) of
                {error, _} = E1 ->
                    E1;
                ok ->
                    Data2 =
                        case SigType of
                            16#00 -> Data;
                            16#01 -> openpgp_text:canonicalize_text(Data)
                        end,
                    verify_hash_and_sig(Data2, Info, PubKey)
            end
    end.

check_sig_type(SigType, Opts) ->
    case maps:find(sig_type, Opts) of
        {ok, SigType} -> ok;
        {ok, _Expected} -> bad_sig({unexpected_sig_type, SigType});
        error when SigType =:= 16#00; SigType =:= 16#01 -> ok;
        error -> {error, {unsupported_sig_type, SigType}}
    end.

%% Creation time is mandatory in a v4 signature. A signature made before its
%% key existed, or from the future, or past its own expiration, is rejected.
%% An issuer named by the signature must be the key we verify with.
check_subpackets(#{hashed_sub := Hashed, unhashed_sub := Unhashed}, Opts) ->
    HashedSubs = sig_subpackets(Hashed),
    Now = maps:get(now, Opts, erlang:system_time(second)),
    case lists:keyfind(2, 1, HashedSubs) of
        {2, <<Created:32/big-unsigned>>} ->
            run_checks([
                fun() -> check_created(Created, Now, Opts) end,
                fun() -> check_expiration(Created, Now, HashedSubs) end,
                fun() -> check_issuer(HashedSubs, sig_subpackets(Unhashed), Opts) end
            ]);
        _ ->
            bad_sig(missing_creation_time)
    end.

run_checks([]) ->
    ok;
run_checks([F | T]) ->
    case F() of
        ok -> run_checks(T);
        {error, _} = Err -> Err
    end.

check_created(Created, Now, Opts) ->
    KeyCreated = maps:get(key_created, Opts, 0),
    if
        Created < KeyCreated -> bad_sig(signature_predates_key);
        Created > Now + ?SKEW -> bad_sig(signature_from_the_future);
        true -> ok
    end.

check_expiration(Created, Now, HashedSubs) ->
    case lists:keyfind(3, 1, HashedSubs) of
        {3, <<0:32>>} -> ok;
        {3, <<Lifetime:32/big-unsigned>>} when Now > Created + Lifetime -> bad_sig(signature_expired);
        _ -> ok
    end.

check_issuer(HashedSubs, UnhashedSubs, Opts) ->
    case maps:find(issuer_fpr, Opts) of
        error ->
            ok;
        {ok, Fpr} when is_binary(Fpr), byte_size(Fpr) =:= 20 ->
            Named = named_issuers(HashedSubs, UnhashedSubs),
            case Named =:= [] orelse lists:all(fun(N) -> is_issuer(N, Fpr) end, Named) of
                true -> ok;
                false -> bad_sig(issuer_mismatch)
            end;
        {ok, Other} ->
            {error, {bad_issuer_fpr, Other}}
    end.

%% @doc Issuer subpackets of a signature: fingerprints (33) from the hashed
%% area, key ids (16) from either area.
-spec named_issuers([{non_neg_integer(), binary()}], [{non_neg_integer(), binary()}]) ->
    [{16 | 33, binary()}].
named_issuers(HashedSubs, UnhashedSubs) ->
    [S || {33, _} = S <- HashedSubs] ++ [S || {16, _} = S <- HashedSubs ++ UnhashedSubs].

-spec is_issuer({16 | 33, binary()}, binary()) -> boolean().
is_issuer({33, Data}, Fpr) ->
    Data =:= <<4:8, Fpr/binary>>;
is_issuer({16, KeyId}, Fpr) ->
    KeyId =:= openpgp_fingerprint:keyid_from_fingerprint(Fpr).

verify_hash_and_sig(Prefix, Info, PubKey) ->
    HashedSub = maps:get(hashed_sub, Info),
    PkAlgId = maps:get(pk_alg, Info),
    HashAlgId = maps:get(hash_alg, Info),
    SigType = maps:get(sig_type, Info),
    Hash16 = maps:get(hash16, Info),
    MpiList = maps:get(mpis, Info),
    SigHashedFields =
        iolist_to_binary([
            <<4:8, SigType:8, PkAlgId:8, HashAlgId:8>>,
            <<(byte_size(HashedSub)):16/big-unsigned>>,
            HashedSub
        ]),
    TrailerLen = byte_size(SigHashedFields),
    Trailer = <<4:8, 16#FF:8, TrailerLen:32/big-unsigned>>,
    HashData = iolist_to_binary([Prefix, SigHashedFields, Trailer]),
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

unarmor(Sig0) ->
    Sig = iolist_to_binary(Sig0),
    case is_armored(Sig) of
        true ->
            case openpgp_armor:decode(Sig) of
                {ok, #{data := D}} -> D;
                {error, _} -> throw(malformed_signature)
            end;
        false ->
            Sig
    end.

subpacket(Type, Data) ->
    Len = 1 + byte_size(Data),
    <<Len:8, Type:8, Data/binary>>.

maybe_expiration(Opts) ->
    case maps:find(expires, Opts) of
        error -> [];
        {ok, Secs} when is_integer(Secs), Secs > 0, Secs =< 16#FFFFFFFF ->
            [subpacket(3, <<Secs:32/big-unsigned>>)];
        {ok, Other} -> throw({bad_expires, Other})
    end.

maybe_issuer_fpr(Opts) ->
    case maps:find(issuer_fpr, Opts) of
        error -> [];
        {ok, Fpr} when is_binary(Fpr), byte_size(Fpr) =:= 20 ->
            [subpacket(33, <<4:8, Fpr/binary>>)];
        {ok, Other} ->
            throw({bad_issuer_fpr, Other})
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

%% @doc OpenPGP hash algorithm id and OTP name for a hash we sign with.
%% SHA-1 and SHA-224 are deliberately absent: RFC 9580 forbids SHA-1 in new
%% signatures and GnuPG rejects it, and SHA-224 buys nothing over SHA-256.
-spec hash_alg(atom()) -> {non_neg_integer(), atom()} | {error, term()}.
hash_alg(sha256) -> {8, sha256};
hash_alg(sha384) -> {9, sha384};
hash_alg(sha512) -> {10, sha512};
hash_alg(Other) -> {error, {unsupported_hash, Other}}.

hash_alg_id(8) -> {sha256, <<"SHA256">>};
hash_alg_id(9) -> {sha384, <<"SHA384">>};
hash_alg_id(10) -> {sha512, <<"SHA512">>};
hash_alg_id(Other) -> {error, {unsupported_hash_alg, Other}}.

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

malformed_sig() ->
    {error, #{reason => malformed_signature, message => <<"malformed signature">>}}.

bad_sig() ->
    {error, #{reason => bad_signature, message => <<"bad signature">>}}.

bad_sig(Detail) ->
    {error, #{reason => bad_signature, detail => Detail, message => <<"bad signature">>}}.

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


