%%% @doc Build minimal OpenPGP v4 self-certification signatures (RFC 4880).
%%%
%%% This produces Signature packets that GnuPG accepts for primary keys.
-module(openpgp_sig).

-export([self_cert/4, self_cert/5, subkey_binding/5, primary_key_binding/4]).

% Sig type 0x13: Positive certification of a User ID and Public-Key packet.
-define(SIGTYPE_POSITIVE_CERT, 16#13).
% Sig type 0x18: Subkey Binding Signature.
-define(SIGTYPE_SUBKEY_BINDING, 16#18).
% Sig type 0x19: Primary Key Binding Signature (backsig / cross-cert).
-define(SIGTYPE_PRIMARY_KEY_BINDING, 16#19).

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
    self_cert(Alg, Key, PublicKeyBody, UserId, #{}).

%% @doc Like `self_cert/4`, but accepts options:
%% - `#{key_flags => binary() | 0..255}` to emit Key Flags subpacket (type 27)
%% - `#{key_expiration => non_neg_integer()}` seconds until key expiry (subpacket 9)
-spec self_cert(pubkey_alg(), map(), binary(), binary(), map()) -> #{packet := map(), fingerprint := binary()}.
self_cert(Alg, Key, PublicKeyBody, UserId, Opts) ->
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

    HashedSub0 = [
        subpacket(2, <<Now:32/big-unsigned>>),
        subpacket(33, <<4:8, Fingerprint/binary>>)
    ],
    HashedSub =
        iolist_to_binary(
            case maps:get(key_flags, Opts, undefined) of
                undefined ->
                    maybe_add_expiration(HashedSub0, maps:get(key_expiration, Opts, undefined));
                FlagsBin when is_binary(FlagsBin), byte_size(FlagsBin) >= 1 ->
                    maybe_add_expiration(HashedSub0 ++ [subpacket(27, FlagsBin)], maps:get(key_expiration, Opts, undefined));
                FlagsInt when is_integer(FlagsInt), FlagsInt >= 0, FlagsInt =< 255 ->
                    maybe_add_expiration(HashedSub0 ++ [subpacket(27, <<FlagsInt:8>>)], maps:get(key_expiration, Opts, undefined));
                Other ->
                    error({bad_key_flags, Other})
            end
        ),
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

%% @doc Create a subkey binding signature (sigtype 0x18) binding SubkeyPubBody to PrimaryPubBody.
%%
%% This must be signed by the *primary* key.
%%
%% `PrimaryAlg` determines the public-key algorithm used for signing:
%% - rsa: expects `Key` = #{priv := rsa_priv()}
%% - ed25519: expects `Key` = #{priv := Ed25519Priv32Bin}
%%
%% `SubkeyFlags` is the OpenPGP "Key Flags" subpacket value (subpacket type 27),
%% typically one byte (e.g. 16#02 for "signing").
%%
%% `key_expiration` (Opts) is the subkey expiry in seconds (subpacket type 9).
%%
%% Returns #{packet => PacketMap}.
-spec subkey_binding(pubkey_alg(), map(), binary(), binary(), map()) -> #{packet := map()}.
subkey_binding(PrimaryAlg, Key, PrimaryPubBody, SubkeyPubBody, Opts) ->
    HashAlg = sha512,
    PkAlgId =
        case PrimaryAlg of
            rsa -> 1;
            ed25519 -> 22
        end,
    HashAlgId = 10, % SHA-512
    PrimaryFpr = openpgp_fingerprint:v4_fingerprint(PrimaryPubBody),
    PrimaryKeyId = openpgp_fingerprint:keyid_from_fingerprint(PrimaryFpr),
    Now = maps:get(created, Opts, now_unix()),
    SubkeyFlags = maps:get(subkey_flags, Opts, undefined),
    KeyExpiration = maps:get(key_expiration, Opts, undefined),
    EmbeddedSigBody = maps:get(embedded_sig_body, Opts, undefined),

    HashedSub0 =
        [
            subpacket(2, <<Now:32/big-unsigned>>),
            subpacket(33, <<4:8, PrimaryFpr/binary>>)
        ],
    HashedSub1 =
        case SubkeyFlags of
            undefined ->
                maybe_add_expiration(HashedSub0, KeyExpiration);
            FlagsBin when is_binary(FlagsBin), byte_size(FlagsBin) >= 1 ->
                maybe_add_expiration(HashedSub0 ++ [subpacket(27, FlagsBin)], KeyExpiration);
            FlagsInt when is_integer(FlagsInt), FlagsInt >= 0, FlagsInt =< 255 ->
                maybe_add_expiration(HashedSub0 ++ [subpacket(27, <<FlagsInt:8>>)], KeyExpiration);
            Other ->
                error({bad_subkey_flags, Other})
        end,
    HashedSub =
        case EmbeddedSigBody of
            undefined ->
                iolist_to_binary(HashedSub1);
            Bin when is_binary(Bin), byte_size(Bin) > 0 ->
                % Embedded Signature subpacket (type 32): include the signature packet BODY.
                iolist_to_binary(HashedSub1 ++ [subpacket(32, Bin)]);
            Other2 ->
                error({bad_embedded_sig, Other2})
        end,

    UnhashedSub =
        iolist_to_binary([
            subpacket(16, PrimaryKeyId)
        ]),

    SigHashedFields =
        iolist_to_binary([
            <<4:8, ?SIGTYPE_SUBKEY_BINDING:8, PkAlgId:8, HashAlgId:8>>,
            <<(byte_size(HashedSub)):16/big-unsigned>>,
            HashedSub
        ]),
    SigFields = iolist_to_binary([SigHashedFields, <<(byte_size(UnhashedSub)):16/big-unsigned>>, UnhashedSub]),

    TrailerLen = byte_size(SigHashedFields),
    Trailer = <<4:8, 16#FF:8, TrailerLen:32/big-unsigned>>,

    Prefix = iolist_to_binary([pubkey_prefix(PrimaryPubBody), pubkey_prefix(SubkeyPubBody)]),
    HashData = iolist_to_binary([Prefix, SigHashedFields, Trailer]),
    Digest = crypto:hash(HashAlg, HashData),
    Hash16 = binary:part(Digest, 0, 2),

    SigMPIs =
        case PrimaryAlg of
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
    #{packet => #{tag => 2, format => new, body => Body}}.

%% @doc Create a primary key binding signature (sigtype 0x19) made by the subkey.
%%
%% This is used for "cross-certification" of signing-capable subkeys:
%% it is embedded as a subpacket (type 32) inside the 0x18 subkey binding signature.
%%
%% Returns #{packet => PacketMap}.
-spec primary_key_binding(pubkey_alg(), map(), binary(), binary()) -> #{packet := map()}.
primary_key_binding(SubkeyAlg, Key, PrimaryPubBody, SubkeyPubBody) ->
    HashAlg = sha512,
    PkAlgId =
        case SubkeyAlg of
            rsa -> 1;
            ed25519 -> 22
        end,
    HashAlgId = 10, % SHA-512
    Now = now_unix(),

    HashedSub = iolist_to_binary([subpacket(2, <<Now:32/big-unsigned>>)]),
    UnhashedSub = <<>>,

    SigHashedFields =
        iolist_to_binary([
            <<4:8, ?SIGTYPE_PRIMARY_KEY_BINDING:8, PkAlgId:8, HashAlgId:8>>,
            <<(byte_size(HashedSub)):16/big-unsigned>>,
            HashedSub
        ]),
    SigFields = iolist_to_binary([SigHashedFields, <<(byte_size(UnhashedSub)):16/big-unsigned>>, UnhashedSub]),

    TrailerLen = byte_size(SigHashedFields),
    Trailer = <<4:8, 16#FF:8, TrailerLen:32/big-unsigned>>,

    Prefix = iolist_to_binary([pubkey_prefix(PrimaryPubBody), pubkey_prefix(SubkeyPubBody)]),
    HashData = iolist_to_binary([Prefix, SigHashedFields, Trailer]),
    Digest = crypto:hash(HashAlg, HashData),
    Hash16 = binary:part(Digest, 0, 2),

    SigMPIs =
        case SubkeyAlg of
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
    #{packet => #{tag => 2, format => new, body => Body}}.

%% Internal

subpacket(Type, Data) when is_integer(Type), Type >= 0, Type =< 255, is_binary(Data) ->
    % RFC 4880 signature subpacket length encoding: 1, 2, or 5 octets.
    Len = 1 + byte_size(Data),
    [encode_subpacket_len(Len), <<Type:8>>, Data].

maybe_add_expiration(Subs, undefined) ->
    Subs;
maybe_add_expiration(Subs, Exp) when is_integer(Exp), Exp >= 0, Exp =< 16#FFFFFFFF ->
    Subs ++ [subpacket(9, <<Exp:32/big-unsigned>>)];
maybe_add_expiration(_Subs, Other) ->
    error({bad_key_expiration, Other}).

encode_subpacket_len(Len) when is_integer(Len), Len >= 0, Len < 192 ->
    <<Len:8>>;
encode_subpacket_len(Len) when is_integer(Len), Len >= 192, Len =< 8383 ->
    Len2 = Len - 192,
    First = (Len2 bsr 8) + 192,
    Second = Len2 band 16#FF,
    <<First:8, Second:8>>;
encode_subpacket_len(Len) when is_integer(Len), Len >= 8384 ->
    <<255:8, Len:32/big-unsigned>>.

pubkey_prefix(PubKeyBody) ->
    Len = byte_size(PubKeyBody),
    <<16#99:8, Len:16/big-unsigned, PubKeyBody/binary>>.

userid_prefix(UserId) ->
    Len = byte_size(UserId),
    <<16#B4:8, Len:32/big-unsigned, UserId/binary>>.

now_unix() ->
    erlang:system_time(second).


