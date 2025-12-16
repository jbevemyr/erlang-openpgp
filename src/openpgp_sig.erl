%%% @doc Build minimal OpenPGP v4 self-certification signatures (RFC 4880).
%%%
%%% This produces Signature packets that GnuPG accepts for primary keys.
-module(openpgp_sig).

-export([self_cert/4]).

% Sig type 0x13: Positive certification of a User ID and Public-Key packet.
-define(SIGTYPE_POSITIVE_CERT, 16#13).

-type pubkey_alg() :: rsa | ed25519.

%% @doc Create a self-cert signature packet body for (PublicKeyPacketBody, UserId).
%%
%% `Alg`:
%% - rsa: expects `Key` = #{priv := PrivKeyForCryptoSign}
%% - ed25519: expects `Key` = #{priv := Ed25519Priv32Bin}
%%
%% Returns #{packet => PacketMap, fingerprint => FingerprintBin}.
-spec self_cert(pubkey_alg(), map(), binary(), binary()) -> #{packet := map(), fingerprint := binary()}.
self_cert(Alg, Key, PublicKeyBody, UserId) ->
    HashAlg = sha512,
    PkAlgId =
        case Alg of
            rsa -> 1;
            ed25519 -> 22
        end,
    HashAlgId = 10, % SHA-512
    Fingerprint = openpgp_fingerprint:v4_fingerprint(PublicKeyBody),
    KeyId = openpgp_fingerprint:keyid_from_fingerprint(Fingerprint),
    Now = now_unix(),

    HashedSub = iolist_to_binary([
        subpacket(2, <<Now:32/big-unsigned>>),
        subpacket(33, <<4:8, Fingerprint/binary>>)
    ]),
    UnhashedSub = iolist_to_binary([
        subpacket(16, KeyId)
    ]),

    % Hash covers only the "hashed" portion of the signature fields (RFC 4880),
    % i.e. up to and including hashed subpackets, but NOT the unhashed subpackets.
    SigHashedFields =
        iolist_to_binary([
            <<4:8, ?SIGTYPE_POSITIVE_CERT:8, PkAlgId:8, HashAlgId:8>>,
            <<(byte_size(HashedSub)):16/big-unsigned>>,
            HashedSub
        ]),
    SigFields = iolist_to_binary([SigHashedFields, <<(byte_size(UnhashedSub)):16/big-unsigned>>, UnhashedSub]),

    TrailerLen = byte_size(SigHashedFields),
    Trailer = <<4:8, 16#FF:8, TrailerLen:32/big-unsigned>>,

    Prefix = iolist_to_binary([pubkey_prefix(PublicKeyBody), userid_prefix(UserId)]),
    HashData = iolist_to_binary([Prefix, SigHashedFields, Trailer]),
    Digest = crypto:hash(HashAlg, HashData),
    Hash16 = binary:part(Digest, 0, 2),

    SigMPIs =
        case Alg of
            rsa ->
                Priv = maps:get(priv, Key),
                Sig = crypto:sign(rsa, sha512, HashData, Priv),
                [openpgp_mpi:encode_bin(Sig)];
            ed25519 ->
                Priv32 = maps:get(priv, Key),
                Sig64 = crypto:sign(eddsa, none, Digest, [Priv32, ed25519]),
                <<R:32/binary, S:32/binary>> = Sig64,
                [openpgp_mpi:encode_bin(R), openpgp_mpi:encode_bin(S)]
        end,

    Body = iolist_to_binary([SigFields, Hash16, SigMPIs]),
    #{packet => #{tag => 2, format => new, body => Body}, fingerprint => Fingerprint}.

%% Internal

subpacket(Type, Data) when is_integer(Type), Type >= 0, Type =< 255, is_binary(Data) ->
    % One-octet length encoding is enough for our small subpackets.
    Len = 1 + byte_size(Data),
    <<Len:8, Type:8, Data/binary>>.

pubkey_prefix(PubKeyBody) ->
    Len = byte_size(PubKeyBody),
    <<16#99:8, Len:16/big-unsigned, PubKeyBody/binary>>.

userid_prefix(UserId) ->
    Len = byte_size(UserId),
    <<16#B4:8, Len:32/big-unsigned, UserId/binary>>.

now_unix() ->
    erlang:system_time(second).


