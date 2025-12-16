%%% @doc Convert between OpenPGP key blocks and Erlang/OTP crypto key formats.
%%%
%%% Supported:
%%% - RSA (OpenPGP public-key alg 1)
%%% - Ed25519 (OpenPGP public-key alg 22 with Ed25519 OID)
%%%
%%% Import:
%%%   {ok, {rsa, [E,N]}} = openpgp_crypto:import_public(ArmoredOrBinary).
%%%   {ok, {ed25519, Pub32}} = openpgp_crypto:import_public(ArmoredOrBinary).
%%%
%%% Export (public key block):
%%%   {ok, Armored, Fpr} = openpgp_crypto:export_public({rsa, [E,N]}, #{userid => <<"me <me@x>">>, signing_key => Priv}).
%%%   {ok, Armored, Fpr} = openpgp_crypto:export_public({ed25519, Pub32}, #{userid => <<"me <me@x>">>, signing_key => Priv32}).
-module(openpgp_crypto).

-include_lib("public_key/include/public_key.hrl").

-export([
    import_public/1,
    import_keypair/1,
    export_public/2,
    export_public_key/2,
    export_secret/2,
    export_secret_key/2
]).

-type rsa_pub() :: [binary()]. % [E,N] as returned by crypto:generate_key/2
-type rsa_priv() :: [binary()]. % [E,N,D,P,Q,DP,DQ,QInv] as returned by crypto:generate_key/2
-type ed_pub() :: binary().  % 32 bytes
-type ed_priv() :: binary(). % 32 bytes

-type crypto_pub() :: {rsa, rsa_pub()} | {ed25519, ed_pub()}.
-type crypto_priv() :: {rsa, rsa_priv()} | {ed25519, {ed_pub(), ed_priv()}}.

-type export_opts() :: #{
    userid := iodata() | binary(),
    created => non_neg_integer(),
    % Optional: if present we add a self-cert signature.
    signing_key => rsa_priv() | ed_priv()
}.

%% @doc Export an unencrypted secret OpenPGP key block from OTP crypto key formats.
%%
%% RSA expects `{rsa, Priv}` where `Priv` is the list returned by `crypto:generate_key(rsa, ...)`.
%% Ed25519 expects `{ed25519, {Pub32, Priv32}}`.
-spec export_secret(crypto_priv(), export_opts()) -> {ok, binary(), binary()} | {error, term()}.
export_secret({rsa, Priv = [E, N, D, P, Q | _]}, Opts) when is_binary(E), is_binary(N), is_binary(D), is_binary(P), is_binary(Q) ->
    UserId = iolist_to_binary(maps:get(userid, Opts)),
    Created = maps:get(created, Opts, erlang:system_time(second)),
    PubBody = iolist_to_binary([<<4:8, Created:32/big-unsigned, 1:8>>, openpgp_mpi:encode_bin(N), openpgp_mpi:encode_bin(E)]),
    % OpenPGP secret MPIs for RSA: d, p, q, u (where u = p^{-1} mod q)
    U = binary:encode_unsigned(modinv_int(binary:decode_unsigned(P), binary:decode_unsigned(Q))),
    SecretMPIs =
        iolist_to_binary([
            openpgp_mpi:encode_bin(D),
            openpgp_mpi:encode_bin(P),
            openpgp_mpi:encode_bin(Q),
            openpgp_mpi:encode_bin(U)
        ]),
    Chk = checksum16(SecretMPIs),
    SecBody = iolist_to_binary([PubBody, <<0:8>>, SecretMPIs, <<Chk:16/big-unsigned>>]),
    SecPkt = #{tag => 5, format => new, body => SecBody},
    UidPkt = #{tag => 13, format => new, body => UserId},
    Packets =
        case maps:find(signing_key, Opts) of
            error ->
                [SecPkt, UidPkt];
            {ok, _} ->
                % Self-cert uses the public key; for RSA we can just re-use the caller's signing key.
                #{packet := SigPkt} = openpgp_sig:self_cert(rsa, #{priv => Priv}, PubBody, UserId),
                [SecPkt, UidPkt, SigPkt]
        end,
    Fpr = openpgp_fingerprint:v4_fingerprint(PubBody),
    {ok, gpg_keys:encode_private(Packets), Fpr};
export_secret({ed25519, {Pub32, Priv32}}, Opts) when is_binary(Pub32), byte_size(Pub32) =:= 32, is_binary(Priv32), byte_size(Priv32) =:= 32 ->
    UserId = iolist_to_binary(maps:get(userid, Opts)),
    Created = maps:get(created, Opts, erlang:system_time(second)),
    Oid = ed25519_oid(),
    PubOpaque = <<16#40, Pub32/binary>>,
    PubBody = iolist_to_binary([
        <<4:8, Created:32/big-unsigned, 22:8>>,
        <<(byte_size(Oid)):8, Oid/binary>>,
        openpgp_mpi:encode_bin(PubOpaque)
    ]),
    SecMPIs = openpgp_mpi:encode_bin(Priv32),
    Chk = checksum16(SecMPIs),
    SecBody = iolist_to_binary([PubBody, <<0:8>>, SecMPIs, <<Chk:16/big-unsigned>>]),
    SecPkt = #{tag => 5, format => new, body => SecBody},
    UidPkt = #{tag => 13, format => new, body => UserId},
    Packets =
        case maps:find(signing_key, Opts) of
            error ->
                [SecPkt, UidPkt];
            {ok, Priv32b} when is_binary(Priv32b), byte_size(Priv32b) =:= 32 ->
                #{packet := SigPkt} = openpgp_sig:self_cert(ed25519, #{priv => Priv32b}, PubBody, UserId),
                [SecPkt, UidPkt, SigPkt];
            {ok, Other} ->
                return_error({bad_signing_key, Other})
        end,
    Fpr = openpgp_fingerprint:v4_fingerprint(PubBody),
    {ok, gpg_keys:encode_private(Packets), Fpr};
export_secret(Other, _Opts) ->
    {error, {unsupported_secret_key, Other}}.

%% @doc Import public key from an armored OpenPGP key block (or raw packet bytes).
-spec import_public(iodata() | binary()) -> {ok, crypto_pub()} | {error, term()}.
import_public(Input) ->
    case gpg_keys:decode(Input) of
        {ok, #{packets := Packets}} ->
            case find_packet(6, Packets) of
                {ok, Body} ->
                    parse_public_key_body(Body);
                error ->
                    {error, no_public_key_packet}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Import secret key if present (unencrypted only). Falls back to public-only.
-spec import_keypair(iodata() | binary()) -> {ok, #{public := crypto_pub(), secret := crypto_priv() | undefined}} | {error, term()}.
import_keypair(Input) ->
    case gpg_keys:decode(Input) of
        {ok, #{packets := Packets}} ->
            case find_packet(6, Packets) of
                {ok, PubBody} ->
                    case parse_public_key_body(PubBody) of
                        {ok, PubKey = {rsa, [E, N]}} ->
                            Secret =
                                case find_packet(5, Packets) of
                                    {ok, SecBody} ->
                                        parse_rsa_secret_key_body(E, N, SecBody);
                                    error ->
                                        {ok, undefined}
                                end,
                            case Secret of
                                {ok, undefined} ->
                                    {ok, #{public => PubKey, secret => undefined}};
                                {ok, Priv} ->
                                    {ok, #{public => PubKey, secret => {rsa, Priv}}};
                                {error, _} = Err ->
                                    Err
                            end;
                        {ok, PubKey = {ed25519, Pub32}} ->
                            Secret =
                                case find_packet(5, Packets) of
                                    {ok, SecBody} ->
                                        parse_ed25519_secret_key_body(Pub32, SecBody);
                                    error ->
                                        {ok, undefined}
                                end,
                            case Secret of
                                {ok, undefined} ->
                                    {ok, #{public => PubKey, secret => undefined}};
                                {ok, Priv32} ->
                                    {ok, #{public => PubKey, secret => {ed25519, {Pub32, Priv32}}}};
                                {error, _} = Err ->
                                    Err
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                error ->
                    {error, no_public_key_packet}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Export a public OpenPGP key block from OTP crypto key formats.
%%
%% If `signing_key` is provided, we add a self-cert signature.
%% Returns `{ok, Armored, Fingerprint}` where Fingerprint is raw 20-byte v4 fingerprint.
-spec export_public(crypto_pub(), export_opts()) -> {ok, binary(), binary()} | {error, term()}.
export_public({rsa, [E, N]}, Opts) when is_binary(E), is_binary(N) ->
    UserId = iolist_to_binary(maps:get(userid, Opts)),
    Created = maps:get(created, Opts, erlang:system_time(second)),
    PubBody = iolist_to_binary([<<4:8, Created:32/big-unsigned, 1:8>>, openpgp_mpi:encode_bin(N), openpgp_mpi:encode_bin(E)]),
    PubPkt = #{tag => 6, format => new, body => PubBody},
    UidPkt = #{tag => 13, format => new, body => UserId},
    Packets =
        case maps:find(signing_key, Opts) of
            error ->
                [PubPkt, UidPkt];
            {ok, Priv} ->
                #{packet := SigPkt} = openpgp_sig:self_cert(rsa, #{priv => Priv}, PubBody, UserId),
                [PubPkt, UidPkt, SigPkt]
        end,
    Fpr = openpgp_fingerprint:v4_fingerprint(PubBody),
    {ok, gpg_keys:encode_public(Packets), Fpr};
export_public({ed25519, Pub32}, Opts) when is_binary(Pub32), byte_size(Pub32) =:= 32 ->
    UserId = iolist_to_binary(maps:get(userid, Opts)),
    Created = maps:get(created, Opts, erlang:system_time(second)),
    Oid = ed25519_oid(),
    PubOpaque = <<16#40, Pub32/binary>>,
    PubBody = iolist_to_binary([
        <<4:8, Created:32/big-unsigned, 22:8>>,
        <<(byte_size(Oid)):8, Oid/binary>>,
        openpgp_mpi:encode_bin(PubOpaque)
    ]),
    PubPkt = #{tag => 6, format => new, body => PubBody},
    UidPkt = #{tag => 13, format => new, body => UserId},
    Packets =
        case maps:find(signing_key, Opts) of
            error ->
                [PubPkt, UidPkt];
            {ok, Priv32} when is_binary(Priv32), byte_size(Priv32) =:= 32 ->
                #{packet := SigPkt} = openpgp_sig:self_cert(ed25519, #{priv => Priv32}, PubBody, UserId),
                [PubPkt, UidPkt, SigPkt];
            {ok, Other} ->
                return_error({bad_signing_key, Other})
        end,
    Fpr = openpgp_fingerprint:v4_fingerprint(PubBody),
    {ok, gpg_keys:encode_public(Packets), Fpr};
export_public(Other, _Opts) ->
    {error, {unsupported_key, Other}}.

%% @doc Export a public OpenPGP key block from common `public_key` record formats.
%%
%% Supported inputs:
%% - `#'RSAPublicKey'{modulus=N, publicExponent=E}`
%% - `#'RSAPrivateKey'{...}` (uses public fields; if full private fields exist and
%%   Opts lacks `signing_key`, we use it to self-sign)
%% - `{#'ECPoint'{point=Pub}, {namedCurve, Oid}}` for Ed25519
%% - `#'ECPrivateKey'{publicKey = #'ECPoint'{...}, parameters = {namedCurve, Oid}, ...}` for Ed25519
%%
%% Returns `{ok, Armored, Fingerprint}`.
-spec export_public_key(term(), export_opts()) -> {ok, binary(), binary()} | {error, term()}.
export_public_key(#'RSAPublicKey'{modulus = N, publicExponent = E}, Opts) ->
    export_public({rsa, [bin_u(E), bin_u(N)]}, Opts);
export_public_key(#'RSAPrivateKey'{} = RsaPrivRec, Opts0) ->
    % Derive public from record and optionally self-sign if private components are present.
    Pub = {rsa, [bin_u(RsaPrivRec#'RSAPrivateKey'.publicExponent), bin_u(RsaPrivRec#'RSAPrivateKey'.modulus)]},
    Opts =
        case maps:is_key(signing_key, Opts0) of
            true ->
                Opts0;
            false ->
                case rsa_priv_record_to_crypto(RsaPrivRec) of
                    {ok, PrivCrypto} -> Opts0#{signing_key => PrivCrypto};
                    {error, _} -> Opts0
                end
        end,
    export_public(Pub, Opts);
export_public_key(#'ECPrivateKey'{publicKey = #'ECPoint'{point = Pub0}, parameters = {namedCurve, Oid}} = EcPriv, Opts0) ->
    case is_ed25519_curve(Oid) of
        true ->
            Pub32 = ed25519_pub32(Pub0),
            Opts =
                case maps:is_key(signing_key, Opts0) of
                    true ->
                        Opts0;
                    false ->
                        case ed25519_priv_record_to_crypto(EcPriv) of
                            {ok, Priv32} -> Opts0#{signing_key => Priv32};
                            {error, _} -> Opts0
                        end
                end,
            export_public({ed25519, Pub32}, Opts);
        false ->
            {error, {unsupported_curve, Oid}}
    end;
% Some OTP versions / callers may pass the raw tuple form of ECPrivateKey for Ed25519:
% {'ECPrivateKey',Version,PrivateKey,{namedCurve,Oid},PublicKey[,Attrs]}
export_public_key({'ECPrivateKey', _Ver, PrivField, {namedCurve, Oid}, PubField} = EcPrivT, Opts0) ->
    export_public_key_ecprivate_tuple(EcPrivT, PrivField, Oid, PubField, Opts0);
export_public_key({'ECPrivateKey', _Ver, PrivField, {namedCurve, Oid}, PubField, _Attrs} = EcPrivT, Opts0) ->
    export_public_key_ecprivate_tuple(EcPrivT, PrivField, Oid, PubField, Opts0);
export_public_key({#'ECPoint'{point = Pub0}, {namedCurve, Oid}} = _PubKey, Opts) ->
    case is_ed25519_curve(Oid) of
        true ->
            Pub32 = ed25519_pub32(Pub0),
            export_public({ed25519, Pub32}, Opts);
        false ->
            {error, {unsupported_curve, Oid}}
    end;
export_public_key(Other, _Opts) ->
    {error, {unsupported_key_record, Other}}.

%% @doc Export an unencrypted secret OpenPGP key block from common `public_key` record formats.
-spec export_secret_key(term(), export_opts()) -> {ok, binary(), binary()} | {error, term()}.
export_secret_key(#'RSAPrivateKey'{} = RsaPrivRec, Opts0) ->
    case rsa_priv_record_to_crypto(RsaPrivRec) of
        {ok, PrivCrypto} ->
            Opts =
                case maps:is_key(signing_key, Opts0) of
                    true -> Opts0;
                    false -> Opts0#{signing_key => PrivCrypto}
                end,
            export_secret({rsa, PrivCrypto}, Opts);
        {error, _} = Err ->
            Err
    end;
export_secret_key(#'ECPrivateKey'{publicKey = #'ECPoint'{point = Pub0}, parameters = {namedCurve, Oid}} = EcPriv, Opts0) ->
    case is_ed25519_curve(Oid) of
        true ->
            Pub32 = ed25519_pub32(Pub0),
            case ed25519_priv_record_to_crypto(EcPriv) of
                {ok, Priv32} ->
                    Opts =
                        case maps:is_key(signing_key, Opts0) of
                            true -> Opts0;
                            false -> Opts0#{signing_key => Priv32}
                        end,
                    export_secret({ed25519, {Pub32, Priv32}}, Opts);
                {error, _} = Err ->
                    Err
            end;
        false ->
            {error, {unsupported_curve, Oid}}
    end;
% Raw tuple ECPrivateKey (Ed25519) support:
export_secret_key({'ECPrivateKey', _Ver, PrivField, {namedCurve, Oid}, PubField}, Opts0) ->
    export_secret_key_ecprivate_tuple(PrivField, Oid, PubField, Opts0);
export_secret_key({'ECPrivateKey', _Ver, PrivField, {namedCurve, Oid}, PubField, _Attrs}, Opts0) ->
    export_secret_key_ecprivate_tuple(PrivField, Oid, PubField, Opts0);
export_secret_key(Other, _Opts) ->
    {error, {unsupported_secret_key_record, Other}}.

%% Internal parsing

find_packet(Tag, Packets) ->
    case [maps:get(body, P) || P <- Packets, maps:get(tag, P) =:= Tag] of
        [Body | _] -> {ok, Body};
        [] -> error
    end.

parse_public_key_body(<<4:8, _Created:32/big-unsigned, 1:8, Rest/binary>>) ->
    % RSA
    case openpgp_mpi:decode_one(Rest) of
        {ok, {_BitsN, N, Rest2}} ->
            case openpgp_mpi:decode_one(Rest2) of
                {ok, {_BitsE, E, <<>>}} ->
                    {ok, {rsa, [E, N]}};
                _ ->
                    {error, bad_rsa_public_key}
            end;
        _ ->
            {error, bad_rsa_public_key}
    end;
parse_public_key_body(<<4:8, _Created:32/big-unsigned, 22:8, OidLen:8, Oid:OidLen/binary, Rest/binary>>) ->
    case Oid =:= ed25519_oid() of
        false ->
            {error, {unsupported_oid, Oid}};
        true ->
            case openpgp_mpi:decode_one(Rest) of
                {ok, {_Bits, Opaque, <<>>}} ->
                    case Opaque of
                        <<16#40, Pub32:32/binary>> ->
                            {ok, {ed25519, Pub32}};
                        _ ->
                            {error, bad_ed25519_public}
                    end;
                _ ->
                    {error, bad_ed25519_public}
            end
    end;
parse_public_key_body(_Other) ->
    {error, unsupported_public_key_format}.

parse_rsa_secret_key_body(E, N, SecBody) when is_binary(E), is_binary(N), is_binary(SecBody) ->
    % Secret-Key packet body starts with the Public-Key body, then S2K usage octet.
    case SecBody of
        <<4:8, _Created:32/big-unsigned, 1:8, Rest0/binary>> ->
            % Parse N,E and keep the remainder (s2k + secret).
            case openpgp_mpi:decode_one(Rest0) of
                {ok, {_BitsN, N2, Rest1}} ->
                    case openpgp_mpi:decode_one(Rest1) of
                        {ok, {_BitsE, E2, Rest2}} ->
                            case {N2, E2} of
                                {N, E} -> parse_rsa_secret_after_pub(Rest2, E, N);
                                _ -> {error, secret_public_mismatch}
                            end;
                        _ -> {error, bad_rsa_secret}
                    end;
                _ -> {error, bad_rsa_secret}
            end;
        _ ->
            {error, bad_rsa_secret}
    end.

parse_rsa_secret_after_pub(<<S2K:8, Tail/binary>>, E, N) ->
    case S2K of
        0 ->
            % d, p, q, u and a 16-bit checksum over secret MPI bytes (NOT incl checksum).
            case decode_mpis(Tail, 4) of
                {ok, {Mpis, AfterMPIs}} ->
                    case AfterMPIs of
                        <<Chk:16/big-unsigned>> ->
                            Sum = checksum16(openpgp_mpis_to_encoded(Mpis)),
                            case (Chk band 16#FFFF) =:= Sum of
                                true ->
                                    [{_Bd, D}, {_Bp, P}, {_Bq, Q}, {_Bu, _U}] = Mpis,
                                    Dint = binary:decode_unsigned(D),
                                    Pint = binary:decode_unsigned(P),
                                    Qint = binary:decode_unsigned(Q),
                                    DP = binary:encode_unsigned(Dint rem (Pint - 1)),
                                    DQ = binary:encode_unsigned(Dint rem (Qint - 1)),
                                    QInv = binary:encode_unsigned(modinv(Qint, Pint)),
                                    {ok, [E, N, D, P, Q, DP, DQ, QInv]};
                                false ->
                                    {error, bad_checksum}
                            end;
                        _ ->
                            {error, bad_rsa_secret_checksum}
                    end;
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, encrypted_secret_key}
    end.

parse_ed25519_secret_key_body(Pub32, SecBody) when is_binary(Pub32), is_binary(SecBody) ->
    case SecBody of
        <<4:8, _Created:32/big-unsigned, 22:8, OidLen:8, Oid:OidLen/binary, Rest0/binary>> ->
            case Oid =:= ed25519_oid() of
                false -> {error, {unsupported_oid, Oid}};
                true ->
                    case openpgp_mpi:decode_one(Rest0) of
                        {ok, {_Bits, Opaque, Rest1}} ->
                            case Opaque of
                                <<16#40, Pub2:32/binary>> when Pub2 =:= Pub32 ->
                                    parse_ed_secret_after_pub(Rest1);
                                _ ->
                                    {error, secret_public_mismatch}
                            end;
                        _ ->
                            {error, bad_ed25519_secret}
                    end
            end;
        _ ->
            {error, bad_ed25519_secret}
    end.

parse_ed_secret_after_pub(<<S2K:8, Tail/binary>>) ->
    case S2K of
        0 ->
            case decode_mpis(Tail, 1) of
                {ok, {[{_Bits, Priv}], After}} ->
                    case After of
                        <<Chk:16/big-unsigned>> ->
                            Sum = checksum16(openpgp_mpis_to_encoded([{0, Priv}])),
                            case (Chk band 16#FFFF) =:= Sum of
                                true ->
                                    case byte_size(Priv) of
                                        32 -> {ok, Priv};
                                        _ -> {error, bad_ed25519_priv_size}
                                    end;
                                false ->
                                    {error, bad_checksum}
                            end;
                        _ ->
                            {error, bad_ed25519_secret_checksum}
                    end;
                {ok, _} ->
                    {error, bad_ed25519_secret};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, encrypted_secret_key}
    end.

decode_mpis(Bin, Count) ->
    decode_mpis(Bin, Count, []).

decode_mpis(Rest, 0, Acc) ->
    {ok, {lists:reverse(Acc), Rest}};
decode_mpis(Bin, N, Acc) when N > 0 ->
    case openpgp_mpi:decode_one(Bin) of
        {ok, {Bits, Val, Tail}} ->
            decode_mpis(Tail, N - 1, [{Bits, Val} | Acc]);
        {error, _} = Err ->
            Err
    end.

openpgp_mpis_to_encoded(Mpis) ->
    iolist_to_binary([openpgp_mpi:encode_bin(V) || {_Bits, V} <- Mpis]).

checksum16(Bin) ->
    checksum16(Bin, 0) band 16#FFFF.

checksum16(<<>>, Sum) ->
    Sum;
checksum16(<<Byte:8, Rest/binary>>, Sum) ->
    checksum16(Rest, Sum + Byte).

modinv_int(A, M) ->
    modinv(A, M).

egcd(0, B) ->
    {B, 0, 1};
egcd(A, B) ->
    {G, X1, Y1} = egcd(B rem A, A),
    {G, Y1 - (B div A) * X1, X1}.

modinv(A, M) ->
    {G, X, _Y} = egcd(A, M),
    case G of
        1 -> ((X rem M) + M) rem M;
        _ -> error({no_inverse, A, M})
    end.

ed25519_oid() ->
    % Same bytes as used in openpgp_keygen.
    <<16#2B, 16#06, 16#01, 16#04, 16#01, 16#DA, 16#47, 16#0F, 16#01>>.

return_error(Reason) ->
    {error, Reason}.

%% Record/curve helpers

bin_u(I) when is_integer(I), I >= 0 -> binary:encode_unsigned(I);
bin_u(B) when is_binary(B) -> B.

is_ed25519_curve(Oid) ->
    try pubkey_cert_records:namedCurves(ed25519) of
        Oid2 -> Oid =:= Oid2
    catch _:_ ->
        false
    end.

ed25519_pub32(Pub) when is_binary(Pub), byte_size(Pub) =:= 32 ->
    Pub;
ed25519_pub32({0, Pub}) when is_binary(Pub), byte_size(Pub) =:= 32 ->
    Pub;
ed25519_pub32(Other) ->
    error({bad_ed25519_public, Other}).

rsa_priv_record_to_crypto(R) ->
    % Only succeeds if all private components exist in the record.
    try
        N = bin_u(R#'RSAPrivateKey'.modulus),
        E = bin_u(R#'RSAPrivateKey'.publicExponent),
        D = bin_u(R#'RSAPrivateKey'.privateExponent),
        P = bin_u(R#'RSAPrivateKey'.prime1),
        Q = bin_u(R#'RSAPrivateKey'.prime2),
        DP = bin_u(R#'RSAPrivateKey'.exponent1),
        DQ = bin_u(R#'RSAPrivateKey'.exponent2),
        QInv = bin_u(R#'RSAPrivateKey'.coefficient),
        {ok, [E, N, D, P, Q, DP, DQ, QInv]}
    catch _:_ ->
        {error, incomplete_rsa_private}
    end.

ed25519_priv_record_to_crypto(#'ECPrivateKey'{privateKey = Priv0}) ->
    % In public_key records this is often an INTEGER for classic EC, but for
    % ed25519 it is typically already 32 bytes.
    case Priv0 of
        Priv when is_binary(Priv), byte_size(Priv) =:= 32 ->
            {ok, Priv};
        I when is_integer(I), I >= 0 ->
            Bin = binary:encode_unsigned(I),
            case byte_size(Bin) =< 32 of
                true -> {ok, leftpad32(Bin)};
                false -> {error, bad_ed25519_priv_size}
            end;
        Other ->
            {error, {bad_ed25519_private, Other}}
    end.

leftpad32(Bin) when is_binary(Bin), byte_size(Bin) =:= 32 ->
    Bin;
leftpad32(Bin) when is_binary(Bin), byte_size(Bin) < 32 ->
    Pad = 32 - byte_size(Bin),
    <<0:Pad/unit:8, Bin/binary>>.

export_secret_key_ecprivate_tuple(PrivField, Oid, PubField, Opts0) ->
    case is_ed25519_curve(Oid) of
        false ->
            {error, {unsupported_curve, Oid}};
        true ->
            case ed25519_from_ecprivate_tuple_fields(PrivField, PubField) of
                {ok, {Pub32, Priv32}} when is_binary(Priv32), byte_size(Priv32) =:= 32 ->
                    Opts =
                        case maps:is_key(signing_key, Opts0) of
                            true -> Opts0;
                            false -> Opts0#{signing_key => Priv32}
                        end,
                    export_secret({ed25519, {Pub32, Priv32}}, Opts);
                {error, _} ->
                    {error, missing_private_key}
            end
    end.

export_public_key_ecprivate_tuple(_EcPrivT, PrivField, Oid, PubField, Opts0) ->
    case is_ed25519_curve(Oid) of
        false ->
            {error, {unsupported_curve, Oid}};
        true ->
            case ed25519_from_ecprivate_tuple_fields(PrivField, PubField) of
                {ok, {Pub32, Priv32OrUndef}} ->
                    Opts =
                        case maps:is_key(signing_key, Opts0) of
                            true -> Opts0;
                            false -> Opts0#{signing_key => Priv32OrUndef}
                        end,
                    export_public({ed25519, Pub32}, Opts);
                {error, _} = Err ->
                    Err
            end
    end.

ed25519_from_ecprivate_tuple_fields(PrivField, PubField) ->
    Pub32 =
        case PubField of
            PubVal when is_binary(PubVal), byte_size(PubVal) =:= 32 -> PubVal;
            asn1_NOVALUE -> undefined;
            _Other -> undefined
        end,
    case PrivField of
        Priv32 when is_binary(Priv32), byte_size(Priv32) =:= 32 ->
            Pub32_2 =
                case Pub32 of
                    undefined ->
                        % Derive pub from priv if possible
                        try crypto:generate_key(eddsa, ed25519, Priv32) of
                            P2 -> P2
                        catch _:_ ->
                            error({missing_ed25519_public})
                        end;
                    PubVal2 -> PubVal2
                end,
            {ok, {Pub32_2, Priv32}};
        % Some OTP/public_key variants encode ed25519 private material as 65 bytes:
        % 1 tag byte + 32 priv + 32 pub
        Bin65 when is_binary(Bin65), byte_size(Bin65) =:= 65 ->
            <<_Tag:8, Priv32:32/binary, Pub32FromPriv:32/binary>> = Bin65,
            Pub32_2 = case Pub32 of undefined -> Pub32FromPriv; PubVal3 -> PubVal3 end,
            {ok, {Pub32_2, Priv32}};
        % Or 64 bytes: 32 priv + 32 pub
        Bin64 when is_binary(Bin64), byte_size(Bin64) =:= 64 ->
            <<Priv32:32/binary, Pub32FromPriv:32/binary>> = Bin64,
            Pub32_2 = case Pub32 of undefined -> Pub32FromPriv; PubVal4 -> PubVal4 end,
            {ok, {Pub32_2, Priv32}};
        _ ->
            {error, bad_ed25519_private_format}
    end.


