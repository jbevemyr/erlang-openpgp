%%% @doc Build OpenPGP v4 key signatures (RFC 4880): self-certifications,
%%% subkey bindings, back signatures, and any other type through
%%% `key_signature/6`.
%%%
%%% This produces Signature packets that GnuPG accepts for primary keys.
-module(openpgp_sig).

-export([self_cert/4, self_cert/5, subkey_binding/5, primary_key_binding/4, key_signature/6, subpacket/2]).

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
%%
%% The algorithm preferences and features are those of GnuPG, without the
%% algorithms RFC 9580 deprecates.
-spec self_cert(pubkey_alg(), map(), binary(), binary(), map()) -> #{packet := map(), fingerprint := binary()}.
self_cert(Alg, Key, PublicKeyBody, UserId, Opts) ->
    Fingerprint = openpgp_fingerprint:v4_fingerprint(PublicKeyBody),
    KeyId = openpgp_fingerprint:keyid_from_fingerprint(Fingerprint),
    HashedSub0 = [
        subpacket(2, <<(created(Opts, [PublicKeyBody])):32/big-unsigned>>),
        subpacket(33, <<4:8, Fingerprint/binary>>),
        % AES-256, AES-192, AES-128
        subpacket(11, <<9, 8, 7>>),
        % SHA-512, SHA-384, SHA-256, SHA-224
        subpacket(21, <<10, 9, 8, 11>>),
        % ZLIB, BZip2, ZIP
        subpacket(22, <<2, 3, 1>>),
        % Modification Detection
        subpacket(30, <<16#01>>)
    ],
    HashedSub =
        case maps:get(key_flags, Opts, undefined) of
            undefined ->
                maybe_add_expiration(HashedSub0, maps:get(key_expiration, Opts, undefined));
            FlagsBin when is_binary(FlagsBin), byte_size(FlagsBin) >= 1 ->
                maybe_add_expiration(HashedSub0 ++ [subpacket(27, FlagsBin)], maps:get(key_expiration, Opts, undefined));
            FlagsInt when is_integer(FlagsInt), FlagsInt >= 0, FlagsInt =< 255 ->
                maybe_add_expiration(HashedSub0 ++ [subpacket(27, <<FlagsInt:8>>)], maps:get(key_expiration, Opts, undefined));
            Other ->
                error({bad_key_flags, Other})
        end,
    Prefix = iolist_to_binary([pubkey_prefix(PublicKeyBody), userid_prefix(UserId)]),
    Packet = key_signature(Alg, Key, ?SIGTYPE_POSITIVE_CERT, Prefix, HashedSub, [subpacket(16, KeyId)]),
    #{packet => Packet, fingerprint => Fingerprint}.

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
    PrimaryFpr = openpgp_fingerprint:v4_fingerprint(PrimaryPubBody),
    PrimaryKeyId = openpgp_fingerprint:keyid_from_fingerprint(PrimaryFpr),
    SubkeyFlags = maps:get(subkey_flags, Opts, undefined),
    KeyExpiration = maps:get(key_expiration, Opts, undefined),
    EmbeddedSigBody = maps:get(embedded_sig_body, Opts, undefined),

    HashedSub0 =
        [
            subpacket(2, <<(created(Opts, [PrimaryPubBody, SubkeyPubBody])):32/big-unsigned>>),
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
                HashedSub1;
            Bin when is_binary(Bin), byte_size(Bin) > 0 ->
                % Embedded Signature subpacket (type 32): include the signature packet BODY.
                HashedSub1 ++ [subpacket(32, Bin)];
            Other2 ->
                error({bad_embedded_sig, Other2})
        end,
    Prefix = iolist_to_binary([pubkey_prefix(PrimaryPubBody), pubkey_prefix(SubkeyPubBody)]),
    #{packet => key_signature(PrimaryAlg, Key, ?SIGTYPE_SUBKEY_BINDING, Prefix, HashedSub, [subpacket(16, PrimaryKeyId)])}.

%% @doc Create a primary key binding signature (sigtype 0x19) made by the subkey.
%%
%% This is used for "cross-certification" of signing-capable subkeys:
%% it is embedded as a subpacket (type 32) inside the 0x18 subkey binding signature.
%%
%% Returns #{packet => PacketMap}.
-spec primary_key_binding(pubkey_alg(), map(), binary(), binary()) -> #{packet := map()}.
primary_key_binding(SubkeyAlg, Key, PrimaryPubBody, SubkeyPubBody) ->
    HashedSub = [subpacket(2, <<(created(#{}, [PrimaryPubBody, SubkeyPubBody])):32/big-unsigned>>)],
    Prefix = iolist_to_binary([pubkey_prefix(PrimaryPubBody), pubkey_prefix(SubkeyPubBody)]),
    #{packet => key_signature(SubkeyAlg, Key, ?SIGTYPE_PRIMARY_KEY_BINDING, Prefix, HashedSub, [])}.

%% @doc A v4 signature packet of `SigType` over `Prefix`, the key-derived data
%% (0x99-framed key bodies, 0xB4-framed User ID) the type calls for, with
%% the given subpackets (see `subpacket/2`). The hashed ones should include
%% a creation time (subpacket 2). Hashed with SHA-512.
-spec key_signature(pubkey_alg(), map(), byte(), binary(), iodata(), iodata()) -> map().
key_signature(Alg, Key, SigType, Prefix, HashedSub0, UnhashedSub0) ->
    PkAlgId =
        case Alg of
            rsa -> 1;
            ed25519 -> 22
        end,
    HashedSub = iolist_to_binary(HashedSub0),
    UnhashedSub = iolist_to_binary(UnhashedSub0),
    SigHashedFields =
        iolist_to_binary([
            <<4:8, SigType:8, PkAlgId:8, 10:8>>,
            <<(byte_size(HashedSub)):16/big-unsigned>>,
            HashedSub
        ]),
    TrailerLen = byte_size(SigHashedFields),
    Trailer = <<4:8, 16#FF:8, TrailerLen:32/big-unsigned>>,
    HashData = iolist_to_binary([Prefix, SigHashedFields, Trailer]),
    Digest = crypto:hash(sha512, HashData),
    SigMPIs =
        case Alg of
            rsa ->
                [openpgp_mpi:encode_bin(crypto:sign(rsa, sha512, HashData, maps:get(priv, Key)))];
            ed25519 ->
                <<R:32/binary, S:32/binary>> = crypto:sign(eddsa, none, Digest, [maps:get(priv, Key), ed25519]),
                [openpgp_mpi:encode_bin(R), openpgp_mpi:encode_bin(S)]
        end,
    Body = iolist_to_binary([
        SigHashedFields,
        <<(byte_size(UnhashedSub)):16/big-unsigned>>,
        UnhashedSub,
        binary:part(Digest, 0, 2),
        SigMPIs
    ]),
    #{tag => 2, format => new, body => Body}.

%% @doc A signature subpacket. Set the critical bit in `Type` (16#80) to make
%% it critical.
-spec subpacket(byte(), binary()) -> iodata().
subpacket(Type, Data) when is_integer(Type), Type >= 0, Type =< 255, is_binary(Data) ->
    % RFC 4880 signature subpacket length encoding: 1, 2, or 5 octets.
    Len = 1 + byte_size(Data),
    [encode_subpacket_len(Len), <<Type:8>>, Data].

%% Internal

%% A signature must not predate the keys it covers, so a key created ahead
%% of the clock gets a signature made at its creation.
created(Opts, KeyBodies) ->
    case maps:find(created, Opts) of
        {ok, Created} ->
            Created;
        error ->
            lists:max([erlang:system_time(second) | [C || <<4:8, C:32/big-unsigned, _/binary>> <- KeyBodies]])
    end.

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
