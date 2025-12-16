%%% @doc Generate minimal OpenPGP v4 primary keys (RSA and Ed25519) in Erlang.
%%%
%%% Produces a key block with:
%%% - Public-Key (tag 6) or Secret-Key (tag 5)
%%% - User ID (tag 13)
%%% - Self-certification Signature (tag 2, type 0x13)
%%%
%%% This is intentionally minimal but sufficient for `gpg --import`.
-module(openpgp_keygen).

-export([
    rsa/1,
    ed25519/1
]).

-type keyblock() :: #{
    public_packets := [openpgp_packets:packet()],
    secret_packets := [openpgp_packets:packet()],
    fingerprint := binary(),
    keyid := binary()
}.

-spec rsa(binary() | iodata()) -> keyblock().
rsa(UserId0) ->
    UserId = iolist_to_binary(UserId0),
    Now = erlang:system_time(second),
    {Pub, Priv} = crypto:generate_key(rsa, {2048, 65537}),
    {Ebin, Nbin} = rsa_pub_parts(Pub),
    {Dbin, Pbin, Qbin} = rsa_priv_parts(Priv),
    Ubin = rsa_u(Pbin, Qbin),

    PubBody = iolist_to_binary([<<4:8, Now:32/big-unsigned, 1:8>>, openpgp_mpi:encode_bin(Nbin), openpgp_mpi:encode_bin(Ebin)]),
    PubPkt = #{tag => 6, format => new, body => PubBody},

    SecretMPIs = iolist_to_binary([
        openpgp_mpi:encode_bin(Dbin),
        openpgp_mpi:encode_bin(Pbin),
        openpgp_mpi:encode_bin(Qbin),
        openpgp_mpi:encode_bin(Ubin)
    ]),
    Chk = checksum16(SecretMPIs),
    SecBody = iolist_to_binary([PubBody, <<0:8>>, SecretMPIs, <<Chk:16/big-unsigned>>]),
    SecPkt = #{tag => 5, format => new, body => SecBody},

    UidPkt = #{tag => 13, format => new, body => UserId},
    #{packet := SigPkt, fingerprint := Fpr} = openpgp_sig:self_cert(rsa, #{priv => Priv}, PubBody, UserId),
    KeyId = openpgp_fingerprint:keyid_from_fingerprint(Fpr),

    #{
        public_packets => [PubPkt, UidPkt, SigPkt],
        secret_packets => [SecPkt, UidPkt, SigPkt],
        fingerprint => Fpr,
        keyid => KeyId
    }.

-spec ed25519(binary() | iodata()) -> keyblock().
ed25519(UserId0) ->
    UserId = iolist_to_binary(UserId0),
    Now = erlang:system_time(second),
    {Pub32, Priv32} = crypto:generate_key(eddsa, ed25519),
    Oid = ed25519_oid(),
    PubOpaque = <<16#40, Pub32/binary>>,
    PubBody = iolist_to_binary([
        <<4:8, Now:32/big-unsigned, 22:8>>,
        <<(byte_size(Oid)):8, Oid/binary>>,
        openpgp_mpi:encode_bin(PubOpaque)
    ]),
    PubPkt = #{tag => 6, format => new, body => PubBody},

    SecretMPIs = openpgp_mpi:encode_bin(Priv32),
    Chk = checksum16(SecretMPIs),
    SecBody = iolist_to_binary([PubBody, <<0:8>>, SecretMPIs, <<Chk:16/big-unsigned>>]),
    SecPkt = #{tag => 5, format => new, body => SecBody},

    UidPkt = #{tag => 13, format => new, body => UserId},
    #{packet := SigPkt, fingerprint := Fpr} = openpgp_sig:self_cert(ed25519, #{priv => Priv32}, PubBody, UserId),
    KeyId = openpgp_fingerprint:keyid_from_fingerprint(Fpr),

    #{
        public_packets => [PubPkt, UidPkt, SigPkt],
        secret_packets => [SecPkt, UidPkt, SigPkt],
        fingerprint => Fpr,
        keyid => KeyId
    }.

%% Internal helpers

rsa_pub_parts([E, N]) when is_binary(E), is_binary(N) -> {E, N};
rsa_pub_parts([E, N | _]) -> {E, N}.

rsa_priv_parts([_E, _N, D, P, Q | _]) -> {D, P, Q}.

rsa_u(Pbin, Qbin) ->
    P = binary:decode_unsigned(Pbin),
    Q = binary:decode_unsigned(Qbin),
    U = modinv(P, Q),
    binary:encode_unsigned(U).

modinv(A, M) ->
    {G, X, _Y} = egcd(A, M),
    case G of
        1 ->
            ((X rem M) + M) rem M;
        _ ->
            error({no_inverse, A, M})
    end.

egcd(0, B) ->
    {B, 0, 1};
egcd(A, B) ->
    {G, X1, Y1} = egcd(B rem A, A),
    {G, Y1 - (B div A) * X1, X1}.

checksum16(Bin) when is_binary(Bin) ->
    checksum16(Bin, 0) band 16#FFFF.

checksum16(<<>>, Sum) ->
    Sum;
checksum16(<<Byte:8, Rest/binary>>, Sum) ->
    checksum16(Rest, Sum + Byte).

ed25519_oid() ->
    % This matches GnuPG’s encoding for Ed25519 primary keys:
    % OID bytes: 2B 06 01 04 01 DA 47 0F 01  (length = 9)
    <<16#2B, 16#06, 16#01, 16#04, 16#01, 16#DA, 16#47, 16#0F, 16#01>>.


