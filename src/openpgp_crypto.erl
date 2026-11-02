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
    import_public_key/1,
    import_public_bundle/1,
    import_public_bundle/2,
    import_public_bundle_key/1,
    crypto_pub_to_public_key/1,
    subkey_flags_to_atoms/1,
    subkey_pub_by_keyid/2,
    import_keypair/1,
    export_public/2,
    export_public_with_subkey/3,
    export_public_key/2,
    export_secret/2,
    export_secret_key/2,
    public_key_info/1,
    fingerprint/2
]).

-type rsa_pub() :: [binary()]. % [E,N] as returned by crypto:generate_key/2
-type rsa_priv() :: [binary()]. % [E,N,D,P,Q,DP,DQ,QInv] as returned by crypto:generate_key/2
-type ed_pub() :: binary().  % 32 bytes
-type ed_priv() :: binary(). % 32 bytes

-type crypto_pub() :: {rsa, rsa_pub()} | {ed25519, ed_pub()}.
-type crypto_priv() :: {rsa, rsa_priv()} | {ed25519, {ed_pub(), ed_priv()}}.

-type public_key_pub() ::
    #'RSAPublicKey'{} | {#'ECPoint'{}, {namedCurve, term()}}.
-type subkey_pub() :: crypto_pub() | public_key_pub().

%% @doc The v4 fingerprint a key gets when exported with the given creation
%% time, without building or signing a key block. Accepts every key form
%% `export_public_key/2` does.
-spec fingerprint(term(), non_neg_integer()) -> {ok, binary()} | {error, term()}.
fingerprint(KeyAny, Created) ->
    case to_crypto_pub(KeyAny) of
        {ok, Pub} -> {ok, openpgp_fingerprint:v4_fingerprint(pubkey_body(Pub, normalize_created(Created)))};
        {error, _} = Err -> Err
    end.

%% @doc Convert an OTP `crypto` public key format to `public_key` record/tuple format.
%%
%% - RSA: `{rsa,[E,N]}` -> `#'RSAPublicKey'{...}`
%% - Ed25519: `{ed25519,Pub32}` -> `{#'ECPoint'{point=Pub32}, {namedCurve, ...}}`
-spec crypto_pub_to_public_key(crypto_pub()) -> {ok, public_key_pub()} | {error, term()}.
crypto_pub_to_public_key({rsa, [Ebin, Nbin]}) when is_binary(Ebin), is_binary(Nbin) ->
    {ok,
        #'RSAPublicKey'{
            modulus = binary:decode_unsigned(Nbin),
            publicExponent = binary:decode_unsigned(Ebin)
        }};
crypto_pub_to_public_key({ed25519, Pub32}) when is_binary(Pub32), byte_size(Pub32) =:= 32 ->
    Params = {namedCurve, pubkey_cert_records:namedCurves(ed25519)},
    {ok, {#'ECPoint'{point = Pub32}, Params}};
crypto_pub_to_public_key(Other) ->
    {error, {unsupported_crypto_public_key, Other}}.

%% @doc Convert a subkey flags bitmask (as returned by `import_public_bundle/1`) to a list of atoms.
%%
%% Input:
%% - `undefined` -> `[]`
%% - integer 0..255 -> list of atoms like `[sign, encrypt_communication]`
%%
%% Note: Order is stable and does not imply preference.
-spec subkey_flags_to_atoms(non_neg_integer() | undefined) -> [atom()].
subkey_flags_to_atoms(undefined) ->
    [];
subkey_flags_to_atoms(I) when is_integer(I), I >= 0 ->
    lists:append([
        maybe_flag(I, 16#01, certify),
        maybe_flag(I, 16#02, sign),
        maybe_flag(I, 16#04, encrypt_communication),
        maybe_flag(I, 16#08, encrypt_storage),
        maybe_flag(I, 16#10, split),
        maybe_flag(I, 16#20, auth)
    ]).

%% @doc Find a subkey public key in a bundle by Key ID.
%%
%% Works for bundles returned by `import_public_bundle/1` and `import_public_bundle_key/1`.
-spec subkey_pub_by_keyid(map(), binary()) -> {ok, subkey_pub()} | {error, term()}.
subkey_pub_by_keyid(Bundle, KeyId) when is_map(Bundle), is_binary(KeyId) ->
    Subkeys = maps:get(subkeys, Bundle, []),
    case [maps:get(pub, S) || S <- Subkeys, maps:get(keyid, S, <<>>) =:= KeyId] of
        [Pub | _] -> {ok, Pub};
        [] -> {error, {no_subkey_keyid, KeyId}}
    end.

maybe_flag(I, Mask, Atom) ->
    case (I band Mask) =:= Mask of
        true -> [Atom];
        false -> []
    end.

%% @doc Normalize OpenPGP v4 timestamps.
%%
%% OpenPGP v4 packets/signatures store "created" time as a 32-bit Unix timestamp in *seconds*.
%% Callers sometimes accidentally pass milliseconds or microseconds; accept those when unambiguous.
-spec normalize_created(non_neg_integer()) -> non_neg_integer().
normalize_created(S) when is_integer(S), S >= 0, S =< 16#FFFFFFFF ->
    S;
normalize_created(Val) when is_integer(Val), Val > 16#FFFFFFFF, Val =< 16#FFFFFFFF * 1000 ->
    % Milliseconds; every later time in milliseconds is too large for 32 bits.
    Val div 1000;
normalize_created(Val) when is_integer(Val), Val > 16#FFFFFFFF * 1000, Val =< 16#FFFFFFFF * 1000000 ->
    % Microseconds; as such, the values below the milliseconds range are
    % times in early 1970, not worth telling apart.
    Val div 1000000;
normalize_created(Val) ->
    error({bad_created_timestamp, Val}).

-type export_opts() :: #{
    userid := iodata() | binary(),
    created => non_neg_integer(),
    % Optional: primary key flags (signature subpacket 27).
    primary_key_flags => binary() | non_neg_integer() | [atom()],
    % Optional: primary key expiration in seconds (signature subpacket 9).
    primary_expires => non_neg_integer(),
    % Optional: alias for primary_expires.
    expires => non_neg_integer(),
    % Optional: if present we add a self-cert signature.
    signing_key => rsa_priv() | ed_priv(),
    % Optional: attach one signing subkey (export as tag 14) with a 0x18 binding signature.
    subkey => term(),
    subkey_created => non_neg_integer(),
    subkey_binding_created => non_neg_integer(),
    subkey_signing_key => term(),
    % Optional: subkey expiration in seconds (signature subpacket 9).
    subkey_expires => non_neg_integer(),
    % Subkey key flags (OpenPGP signature subpacket 27). Usually 1 byte (e.g. 16#02 for signing).
    subkey_flags => binary() | non_neg_integer() | [atom()]
}.

%% @doc Import an OpenPGP public keyblock that may contain a primary key + subkeys.
%%
%% The signatures that tie the block together are verified (see
%% `verify_bundle/3`). A revoked or expired primary key is an error. Only
%% User IDs with a valid, unrevoked self-certification are returned, the
%% primary one first; `self_certified` tells whether there is any, or a
%% valid direct-key signature. Only subkeys with a valid binding that are
%% neither revoked nor expired are returned; the others are listed in
%% `rejected_subkeys` with the reason.
%%
%% Returns:
%% - primary public key in OTP crypto-format
%% - primary fingerprint/keyid/created, and its expiration and key flags
%%   (`undefined` when absent) from its self-signature
%% - the self-certified User IDs (tag 13)
%% - subkeys (tag 14) with fingerprint/created/flags/expires
-spec import_public_bundle(iodata() | binary()) ->
    {ok,
        #{
            primary := crypto_pub(),
            primary_fpr := binary(),
            primary_keyid := binary(),
            primary_created := non_neg_integer(),
            primary_expires := non_neg_integer() | undefined,
            primary_flags := non_neg_integer() | undefined,
            userids := [binary()],
            self_certified := boolean(),
            subkeys := [
                #{
                    pub := crypto_pub(),
                    fpr := binary(),
                    keyid := binary(),
                    created := non_neg_integer(),
                    flags := non_neg_integer() | undefined,
                    expires := non_neg_integer() | undefined
                }
            ],
            rejected_subkeys := [#{keyid := binary() | undefined, reason := term()}]
        }}
    | {error, term()}.
import_public_bundle(Input) ->
    import_public_bundle(Input, #{}).

%% @doc Like `import_public_bundle/1`; `now` in `Opts` is the reference time
%% for expiration (default: the system clock).
-spec import_public_bundle(iodata() | binary(), #{now => non_neg_integer()}) ->
    {ok, map()} | {error, term()}.
import_public_bundle(Input, Opts) ->
    case gpg_keys:decode(Input) of
        {ok, #{packets := Packets0}} ->
            case lists:dropwhile(fun(#{tag := T}) -> T =/= 6 end, Packets0) of
                [#{body := PrimaryBody} | Packets] ->
                    case {public_key_body_info(PrimaryBody), parse_public_key_body(PrimaryBody)} of
                        {{ok, #{created := Created, fingerprint := Fpr, keyid := KeyId}}, {ok, PrimaryPub}} ->
                            Primary = #{
                                body => PrimaryBody,
                                pub => PrimaryPub,
                                fpr => Fpr,
                                keyid => KeyId,
                                created => Created,
                                now => maps:get(now, Opts, erlang:system_time(second))
                            },
                            verify_bundle(Packets, Primary);
                        {{error, _} = Err, _} ->
                            Err;
                        {_, {error, _} = Err} ->
                            Err
                    end;
                [] ->
                    {error, no_public_key_packet}
            end;
        {error, _} = Err ->
            Err
    end.

%% Check the signatures that tie the key block together (RFC 4880 11.1,
%% 5.2.1), the way GnuPG does before it trusts any of it. Signatures that do
%% not verify, are expired, or are made by another key are ignored; only the
%% primary key's own signatures count.
%% - the primary key must not be revoked (0x20), nor expired according to
%%   its latest direct-key signature (0x1F), or else the latest
%%   self-certification of its primary User ID.
%% - a User ID counts when its latest self-certification (0x10-0x13) is not
%%   followed by a certification revocation (0x30).
%% - a subkey counts when its latest binding (0x18) verifies over both keys,
%%   carries a back signature (0x19) by the subkey unless its key flags rule
%%   out signing, and the subkey is neither revoked (0x28) nor expired.
%% Key flags are read from the verified signatures, never from unverified
%% ones.
verify_bundle(Packets, #{body := PrimaryBody, created := Created, now := Now} = Primary) ->
    {KeySigs, Rest} = take_signatures(Packets),
    Components = components(Rest),
    KeyPrefix = pubkey_prefix(PrimaryBody),
    Revocations = valid_self_sigs(KeySigs, KeyPrefix, [16#20], Primary),
    DirectSigs = valid_self_sigs(KeySigs, KeyPrefix, [16#1F], Primary),
    UserIds = certified_userids([{U, S} || {13, U, S} <- Components], Primary),
    SelfSig =
        case {latest(DirectSigs), UserIds} of
            {#{} = Direct, _} -> Direct;
            {undefined, [{_, Cert} | _]} -> Cert;
            {undefined, []} -> undefined
        end,
    Expires = key_expires(SelfSig, Created),
    if
        Revocations =/= [] ->
            {error, key_revoked};
        is_integer(Expires), Expires =< Now ->
            {error, key_expired};
        true ->
            {Subs, Rejected} = verify_subkeys([{B, S} || {14, B, S} <- Components], Primary),
            {ok, #{
                primary => maps:get(pub, Primary),
                primary_fpr => maps:get(fpr, Primary),
                primary_keyid => maps:get(keyid, Primary),
                primary_created => Created,
                primary_expires => Expires,
                primary_flags => key_flags(SelfSig),
                userids => [U || {U, _} <- UserIds],
                self_certified => SelfSig =/= undefined,
                subkeys => Subs,
                rejected_subkeys => Rejected
            }}
    end.

take_signatures(Packets) ->
    lists:splitwith(fun(#{tag := T}) -> T =:= 2 end, Packets).

%% The packets after the primary key's own signatures, grouped as
%% `{Tag, Body, Signatures}`, up to the next primary key, if any.
components(Packets) ->
    components(Packets, []).

components([], Acc) ->
    lists:reverse(Acc);
components([#{tag := 6} | _], Acc) ->
    lists:reverse(Acc);
components([#{tag := Tag, body := Body} | Rest0], Acc) ->
    {Sigs, Rest} = take_signatures(Rest0),
    components(Rest, [{Tag, Body, Sigs} | Acc]).

valid_self_sigs(Sigs, Prefix, Types, #{pub := Pub, created := Created, now := Now} = Primary) ->
    Opts = #{now => Now, key_created => Created},
    [
        Info
     || #{body := B} <- Sigs,
        names_issuer(B, Primary),
        {ok, Info} <- [openpgp_detached_sig:verify_key_signature(Prefix, B, Pub, Types, Opts)]
    ].

latest([]) ->
    undefined;
latest(Infos) ->
    hd(lists:sort(fun(#{created := A}, #{created := B}) -> A >= B end, Infos)).

%% `[{UserId, LatestCertification}]` for the User IDs that count, the
%% primary one first: the one whose certification says so, else the one
%% certified most recently.
certified_userids(UidSigs, #{body := PrimaryBody} = Primary) ->
    Certified =
        lists:filtermap(
            fun({UserId, Sigs}) ->
                Prefix = iolist_to_binary([pubkey_prefix(PrimaryBody), userid_prefix(UserId)]),
                Cert = latest(valid_self_sigs(Sigs, Prefix, [16#10, 16#11, 16#12, 16#13], Primary)),
                Revocation = latest(valid_self_sigs(Sigs, Prefix, [16#30], Primary)),
                case {Cert, Revocation} of
                    {undefined, _} -> false;
                    {#{}, undefined} -> {true, {UserId, Cert}};
                    {#{created := C}, #{created := R}} when R < C -> {true, {UserId, Cert}};
                    _ -> false
                end
            end,
            UidSigs
        ),
    Rank = fun({_, #{created := C} = Cert}) -> {is_primary_userid(Cert), C} end,
    case lists:sort(fun(A, B) -> Rank(A) >= Rank(B) end, Certified) of
        [] -> [];
        [First | _] -> [First | [U || U <- Certified, U =/= First]]
    end.

is_primary_userid(#{hashed_sub := Hashed}) ->
    case openpgp_detached_sig:sig_subpacket(25, Hashed) of
        {ok, <<P:8>>} -> P =/= 0;
        _ -> false
    end.

%% Subpacket 9 is the key's lifetime from its creation; 0 means no expiry.
key_expires(undefined, _Created) ->
    undefined;
key_expires(#{hashed_sub := Hashed}, Created) ->
    case openpgp_detached_sig:sig_subpacket(9, Hashed) of
        {ok, <<0:32>>} -> undefined;
        {ok, <<Lifetime:32/big-unsigned>>} -> Created + Lifetime;
        _ -> undefined
    end.

key_flags(undefined) ->
    undefined;
key_flags(#{hashed_sub := Hashed}) ->
    subkey_flags_from_subpackets(Hashed).

verify_subkeys(SubSigs, Primary) ->
    lists:foldr(
        fun({SubBody, Sigs}, {Subs, Rejected}) ->
            case verify_subkey(SubBody, Sigs, Primary) of
                {ok, Sub} -> {[Sub | Subs], Rejected};
                {error, KeyId, Reason} -> {Subs, [#{keyid => KeyId, reason => Reason} | Rejected]}
            end
        end,
        {[], []},
        SubSigs
    ).

verify_subkey(SubBody, Sigs, #{body := PrimaryBody, now := Now} = Primary) ->
    case {public_key_body_info(SubBody), parse_public_key_body(SubBody)} of
        {{ok, #{created := Created, fingerprint := Fpr, keyid := KeyId}}, {ok, SubPub}} ->
            Prefix = iolist_to_binary([pubkey_prefix(PrimaryBody), pubkey_prefix(SubBody)]),
            Revocations = valid_self_sigs(Sigs, Prefix, [16#28], Primary),
            case verify_binding(Sigs, Prefix, SubPub, Created, Primary) of
                _ when Revocations =/= [] ->
                    {error, KeyId, revoked};
                {ok, Binding} ->
                    case key_expires(Binding, Created) of
                        Expires when is_integer(Expires), Expires =< Now ->
                            {error, KeyId, expired};
                        Expires ->
                            {ok, #{
                                pub => SubPub,
                                fpr => Fpr,
                                keyid => KeyId,
                                created => Created,
                                flags => key_flags(Binding),
                                expires => Expires
                            }}
                    end;
                {error, Reason} ->
                    {error, KeyId, Reason}
            end;
        {{ok, #{keyid := KeyId}}, {error, Reason}} ->
            {error, KeyId, Reason};
        {{error, Reason}, _} ->
            {error, undefined, Reason}
    end.

%% The latest binding by the primary key that verifies, and unless its key
%% flags rule out signing, carries a back signature (0x19) by the subkey.
verify_binding(Sigs, Prefix, SubPub, SubCreated, #{pub := PrimaryPub, created := PrimaryCreated, now := Now}) ->
    Opts = #{now => Now, key_created => max(PrimaryCreated, SubCreated)},
    Results = [
        check_back_signature(R, Prefix, SubPub, Opts#{key_created => SubCreated})
     || #{body := B} <- Sigs,
        R <- [openpgp_detached_sig:verify_key_signature(Prefix, B, PrimaryPub, [16#18], Opts)]
    ],
    case [Info || {ok, Info} <- Results] of
        [_ | _] = Valid -> {ok, latest(Valid)};
        [] when Results =:= [] -> {error, no_binding_signature};
        [] -> hd([E || {error, _} = E <- Results])
    end.

check_back_signature({ok, #{hashed_sub := Hashed, unhashed_sub := Unhashed} = Info}, Prefix, SubPub, Opts) ->
    Flags = subkey_flags_from_subpackets(Hashed),
    case Flags =:= undefined orelse (Flags band 16#02) =:= 16#02 of
        false ->
            {ok, Info};
        true ->
            Embedded = [
                D
             || {32, D} <- openpgp_detached_sig:sig_subpackets(Hashed) ++
                    openpgp_detached_sig:sig_subpackets(Unhashed)
            ],
            Valid = [
                ok
             || D <- Embedded,
                {ok, _} <- [openpgp_detached_sig:verify_key_signature(Prefix, D, SubPub, [16#19], Opts)]
            ],
            case {Valid, Embedded} of
                {[_ | _], _} -> {ok, Info};
                {[], []} -> {error, missing_back_signature};
                {[], _} -> {error, invalid_back_signature}
            end
    end;
check_back_signature({error, _} = Err, _Prefix, _SubPub, _Opts) ->
    Err.

names_issuer(SigBody, #{fpr := Fpr}) ->
    case parse_v4_sig_info(SigBody) of
        {ok, #{hashed_sub := Hashed, unhashed_sub := Unhashed}} ->
            Named = openpgp_detached_sig:named_issuers(openpgp_detached_sig:sig_subpackets(Hashed),
                                                       openpgp_detached_sig:sig_subpackets(Unhashed)),
            %% An unnamed issuer is taken to be the primary key, as GnuPG does.
            Named =:= [] orelse lists:any(fun(N) -> openpgp_detached_sig:is_issuer(N, Fpr) end, Named);
        _ ->
            false
    end.

pubkey_prefix(PubKeyBody) ->
    Len = byte_size(PubKeyBody),
    <<16#99:8, Len:16/big-unsigned, PubKeyBody/binary>>.

userid_prefix(UserId) ->
    Len = byte_size(UserId),
    <<16#B4:8, Len:32/big-unsigned, UserId/binary>>.

%% @doc Like `import_public_bundle/1`, but converts `primary` and each subkey `pub`
%% into `public_key` record/tuple formats (`#'RSAPublicKey'{}` / `{#'ECPoint'{}, Params}`).
-spec import_public_bundle_key(iodata() | binary()) ->
    {ok,
        #{
            primary := public_key_pub(),
            primary_fpr := binary(),
            primary_keyid := binary(),
            primary_created := non_neg_integer(),
            primary_expires := non_neg_integer() | undefined,
            primary_flags := non_neg_integer() | undefined,
            userids := [binary()],
            self_certified := boolean(),
            subkeys := [
                #{
                    pub := public_key_pub(),
                    fpr := binary(),
                    keyid := binary(),
                    created := non_neg_integer(),
                    flags := non_neg_integer() | undefined,
                    expires := non_neg_integer() | undefined
                }
            ],
            rejected_subkeys := [#{keyid := binary() | undefined, reason := term()}]
        }}
    | {error, term()}.
import_public_bundle_key(Input) ->
    case import_public_bundle(Input) of
        {ok, Bundle} ->
            case crypto_pub_to_public_key(maps:get(primary, Bundle)) of
                {ok, PrimaryPk} ->
                    Subkeys0 = maps:get(subkeys, Bundle, []),
                    case convert_subkeys_to_public_key(Subkeys0) of
                        {ok, Subkeys1} ->
                            {ok, Bundle#{primary => PrimaryPk, subkeys => Subkeys1}};
                        {error, _} = Err1 ->
                            Err1
                    end;
                {error, _} = Err0 ->
                    Err0
            end;
        {error, _} = Err ->
            Err
    end.

convert_subkeys_to_public_key(Subkeys) ->
    convert_subkeys_to_public_key(Subkeys, []).

convert_subkeys_to_public_key([], Acc) ->
    {ok, lists:reverse(Acc)};
convert_subkeys_to_public_key([S | Rest], Acc) ->
    case crypto_pub_to_public_key(maps:get(pub, S)) of
        {ok, Pk} ->
            convert_subkeys_to_public_key(Rest, [S#{pub => Pk} | Acc]);
        {error, _} = Err ->
            Err
    end.

%% @doc Extract metadata from a public OpenPGP key block (or raw packet bytes).
%%
%% Returns v4 `created` time (unix seconds) from the Public-Key packet body.
-spec public_key_info(iodata() | binary()) ->
    {ok, #{created := non_neg_integer(), alg := rsa | ed25519 | unknown, fingerprint := binary(), keyid := binary()}}
    | {error, term()}.
public_key_info(Input) ->
    case gpg_keys:decode(Input) of
        {ok, #{packets := Packets}} ->
            case find_packet(6, Packets) of
                {ok, Body} ->
                    public_key_body_info(Body);
                error ->
                    {error, no_public_key_packet}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Export an unencrypted secret OpenPGP key block from OTP crypto key formats.
%%
%% RSA expects `{rsa, Priv}` where `Priv` is the list returned by `crypto:generate_key(rsa, ...)`.
%% Ed25519 expects `{ed25519, {Pub32, Priv32}}`.
-spec export_secret(crypto_priv(), export_opts()) -> {ok, binary(), binary()} | {error, term()}.
export_secret({rsa, [E, N, D, P0, Q0 | _]}, Opts) when is_binary(E), is_binary(N), is_binary(D), is_binary(P0), is_binary(Q0) ->
    Pub = {rsa, [E, N]},
    PubBody = pubkey_body(Pub, normalize_created(maps:get(created, Opts, erlang:system_time(second)))),
    %% OpenPGP has p < q and u = p^-1 mod q (RFC 4880 5.5.3), OTP p > q.
    {P, Q} =
        case binary:decode_unsigned(P0) < binary:decode_unsigned(Q0) of
            true -> {P0, Q0};
            false -> {Q0, P0}
        end,
    U = binary:encode_unsigned(modinv(binary:decode_unsigned(P), binary:decode_unsigned(Q))),
    SecretMPIs =
        iolist_to_binary([
            openpgp_mpi:encode_bin(D),
            openpgp_mpi:encode_bin(P),
            openpgp_mpi:encode_bin(Q),
            openpgp_mpi:encode_bin(U)
        ]),
    export_secret_block(Pub, rsa, PubBody, SecretMPIs, Opts);
export_secret({ed25519, {Pub32, Priv32}}, Opts) when is_binary(Pub32), byte_size(Pub32) =:= 32, is_binary(Priv32), byte_size(Priv32) =:= 32 ->
    Pub = {ed25519, Pub32},
    PubBody = pubkey_body(Pub, normalize_created(maps:get(created, Opts, erlang:system_time(second)))),
    export_secret_block(Pub, ed25519, PubBody, openpgp_mpi:encode_bin(Priv32), Opts);
export_secret(Other, _Opts) ->
    {error, {unsupported_secret_key, Other}}.

export_secret_block(Pub, Alg, PubBody, SecretMPIs, Opts) ->
    UserId = iolist_to_binary(maps:get(userid, Opts)),
    Chk = checksum16(SecretMPIs),
    SecBody = iolist_to_binary([PubBody, <<0:8>>, SecretMPIs, <<Chk:16/big-unsigned>>]),
    SecPkt = #{tag => 5, format => new, body => SecBody},
    case key_packets(SecPkt, Pub, Alg, PubBody, UserId, Opts) of
        {ok, Packets} -> {ok, gpg_keys:encode_private(Packets), openpgp_fingerprint:v4_fingerprint(PubBody)};
        {error, _} = Err -> Err
    end.

%% The key packet, the User ID and, given a signing key, its self-certification.
key_packets(KeyPkt, Pub, Alg, PubBody, UserId, Opts) ->
    UidPkt = #{tag => 13, format => new, body => UserId},
    case maps:find(signing_key, Opts) of
        error ->
            case maps:is_key(primary_key_flags, Opts) orelse maps:is_key(primary_expires, Opts) orelse maps:is_key(expires, Opts) of
                true -> {error, missing_signing_key_for_primary_flags};
                false -> {ok, [KeyPkt, UidPkt]}
            end;
        {ok, Priv} ->
            case self_signature(Alg, Priv, Pub, PubBody, UserId, self_cert_opts(Opts)) of
                {ok, SigPkt} -> {ok, [KeyPkt, UidPkt, SigPkt]};
                {error, _} = Err -> Err
            end
    end.

%% A self-certification by another key than Pub would make a key block that
%% no one accepts, so it is checked.
self_signature(Alg, Priv, Pub, PubBody, UserId, SelfCertOpts) ->
    case valid_signing_key(Alg, Priv) of
        false ->
            {error, bad_signing_key};
        true ->
            #{packet := #{body := SigBody} = SigPkt} = openpgp_sig:self_cert(Alg, #{priv => Priv}, PubBody, UserId, SelfCertOpts),
            Prefix = iolist_to_binary([pubkey_prefix(PubBody), userid_prefix(UserId)]),
            case openpgp_detached_sig:verify_key_signature(Prefix, SigBody, Pub, [16#13]) of
                {ok, _} -> {ok, SigPkt};
                {error, _} -> {error, signing_key_mismatch}
            end
    end.

valid_signing_key(rsa, [E, N, D | _]) -> is_binary(E) andalso is_binary(N) andalso is_binary(D);
valid_signing_key(ed25519, Priv32) -> is_binary(Priv32) andalso byte_size(Priv32) =:= 32;
valid_signing_key(_Alg, _Priv) -> false.

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

%% @doc Import a public key and return it in `public_key` record/tuple format:
%% - RSA: `#'RSAPublicKey'{modulus=N, publicExponent=E}`
%% - Ed25519: `{#'ECPoint'{point = Pub32}, {namedCurve, pubkey_cert_records:namedCurves(ed25519)}}`
-spec import_public_key(iodata() | binary()) -> {ok, public_key_pub()} | {error, term()}.
import_public_key(Input) ->
    case import_public(Input) of
        {ok, {rsa, [Ebin, Nbin]}} ->
            {ok,
                #'RSAPublicKey'{
                    modulus = binary:decode_unsigned(Nbin),
                    publicExponent = binary:decode_unsigned(Ebin)
                }};
        {ok, {ed25519, Pub32}} ->
            Params = {namedCurve, pubkey_cert_records:namedCurves(ed25519)},
            {ok, {#'ECPoint'{point = Pub32}, Params}};
        {error, _} = Err ->
            Err
    end.

%% @doc Import secret key if present (unencrypted only). Falls back to public-only.
%%
%% Takes a public key block, or a secret one, which has no Public-Key packet.
%% Secret subkeys (tag 7) are not imported.
-spec import_keypair(iodata() | binary()) -> {ok, #{public := crypto_pub(), secret := crypto_priv() | undefined}} | {error, term()}.
import_keypair(Input) ->
    case gpg_keys:decode(Input) of
        {ok, #{packets := Packets}} ->
            case {find_packet(6, Packets), find_packet(5, Packets)} of
                {{ok, PubBody}, Secret} ->
                    import_keypair(PubBody, Secret);
                {error, {ok, SecBody}} ->
                    case secret_public_body(SecBody) of
                        {ok, PubBody} -> import_keypair(PubBody, {ok, SecBody});
                        {error, _} = Err -> Err
                    end;
                {error, error} ->
                    {error, no_public_key_packet}
            end;
        {error, _} = Err ->
            Err
    end.

import_keypair(PubBody, SecretPacket) ->
    case parse_public_key_body(PubBody) of
        {ok, PubKey = {rsa, [E, N]}} ->
            case SecretPacket of
                {ok, SecBody} ->
                    case parse_rsa_secret_key_body(E, N, SecBody) of
                        {ok, Priv} -> {ok, #{public => PubKey, secret => {rsa, Priv}}};
                        {error, _} = Err -> Err
                    end;
                error ->
                    {ok, #{public => PubKey, secret => undefined}}
            end;
        {ok, PubKey = {ed25519, Pub32}} ->
            case SecretPacket of
                {ok, SecBody} ->
                    case parse_ed25519_secret_key_body(Pub32, SecBody) of
                        {ok, Priv32} -> {ok, #{public => PubKey, secret => {ed25519, {Pub32, Priv32}}}};
                        {error, _} = Err -> Err
                    end;
                error ->
                    {ok, #{public => PubKey, secret => undefined}}
            end;
        {error, _} = Err ->
            Err
    end.

%% The Public-Key packet body that a Secret-Key packet body begins with.
secret_public_body(<<4:8, _Created:32/big-unsigned, 1:8, Rest0/binary>> = SecBody) ->
    case openpgp_mpi:decode_one(Rest0) of
        {ok, {_, _N, Rest1}} ->
            case openpgp_mpi:decode_one(Rest1) of
                {ok, {_, _E, Rest2}} -> {ok, binary:part(SecBody, 0, byte_size(SecBody) - byte_size(Rest2))};
                {error, _} -> {error, bad_rsa_secret}
            end;
        {error, _} ->
            {error, bad_rsa_secret}
    end;
secret_public_body(<<4:8, _Created:32/big-unsigned, 22:8, OidLen:8, _Oid:OidLen/binary, Rest0/binary>> = SecBody) ->
    case openpgp_mpi:decode_one(Rest0) of
        {ok, {_, _Q, Rest1}} -> {ok, binary:part(SecBody, 0, byte_size(SecBody) - byte_size(Rest1))};
        {error, _} -> {error, bad_ed25519_secret}
    end;
secret_public_body(_) ->
    {error, unsupported_secret_key_format}.

%% @doc Export a public OpenPGP key block from OTP crypto key formats.
%%
%% If `signing_key` is provided, we add a self-cert signature.
%% Returns `{ok, Armored, Fingerprint}` where Fingerprint is raw 20-byte v4 fingerprint.
-spec export_public(crypto_pub(), export_opts()) -> {ok, binary(), binary()} | {error, term()}.
export_public({rsa, [E, N]} = Pub, Opts) when is_binary(E), is_binary(N) ->
    export_public(Pub, rsa, Opts);
export_public({ed25519, Pub32} = Pub, Opts) when is_binary(Pub32), byte_size(Pub32) =:= 32 ->
    export_public(Pub, ed25519, Opts);
export_public(Other, _Opts) ->
    {error, {unsupported_key, Other}}.

export_public(Pub, Alg, Opts) ->
    UserId = iolist_to_binary(maps:get(userid, Opts)),
    PubBody = pubkey_body(Pub, normalize_created(maps:get(created, Opts, erlang:system_time(second)))),
    PubPkt = #{tag => 6, format => new, body => PubBody},
    case key_packets(PubPkt, Pub, Alg, PubBody, UserId, Opts) of
        {ok, Packets} -> {ok, gpg_keys:encode_public(Packets), openpgp_fingerprint:v4_fingerprint(PubBody)};
        {error, _} = Err -> Err
    end.

%% @doc Export a public OpenPGP key block containing a primary key + one subkey.
%%
%% `PrimaryAny` and `SubkeyAny` may be any of the formats supported by `export_public_key/2`,
%% as well as OTP crypto formats:
%% - primary pub: `{rsa,[E,N]}` or `{ed25519,Pub32}`
%% - primary signing key: `Opts#{signing_key => Priv}` must be present or derivable from PrimaryAny
%%
%% This returns `{ok, Armored, #{primary_fpr := Fpr20, subkey_fpr := Fpr20}}`.
-spec export_public_with_subkey(term(), term(), export_opts()) ->
    {ok, binary(), #{primary_fpr := binary(), subkey_fpr := binary()}} | {error, term()}.
export_public_with_subkey(PrimaryAny, SubkeyAny, Opts0) ->
    UserId = iolist_to_binary(maps:get(userid, Opts0)),
    CreatedPrimary = normalize_created(maps:get(created, Opts0, erlang:system_time(second))),
    CreatedSub = normalize_created(maps:get(subkey_created, Opts0, CreatedPrimary)),
    case {to_crypto_pub(PrimaryAny), to_crypto_pub(SubkeyAny), to_primary_signing_key(PrimaryAny, Opts0)} of
        {{ok, PrimaryPub}, {ok, SubPub}, {ok, {PrimaryAlg, PrimaryPriv}}} ->
            PrimaryPubBody = pubkey_body(PrimaryPub, CreatedPrimary),
            SubPubBody = pubkey_body(SubPub, CreatedSub),
            SubkeyFlags = subkey_flags_int(maps:get(subkey_flags, Opts0, 16#02)),
            case self_signature(PrimaryAlg, PrimaryPriv, PrimaryPub, PrimaryPubBody, UserId, self_cert_opts(Opts0)) of
                {ok, SelfSigPkt} ->
                    case back_signature(SubkeyFlags, SubkeyAny, PrimaryPubBody, SubPubBody, Opts0) of
                        {ok, EmbeddedSigBody} ->
                            #{packet := BindSigPkt} =
                                openpgp_sig:subkey_binding(
                                    PrimaryAlg,
                                    #{priv => PrimaryPriv},
                                    PrimaryPubBody,
                                    SubPubBody,
                                    #{
                                        created => normalize_created(
                                            maps:get(subkey_binding_created, Opts0, max(CreatedPrimary, CreatedSub))
                                        ),
                                        subkey_flags => SubkeyFlags,
                                        key_expiration => subkey_expires_seconds(Opts0),
                                        embedded_sig_body => EmbeddedSigBody
                                    }
                                ),
                            Packets = [
                                #{tag => 6, format => new, body => PrimaryPubBody},
                                #{tag => 13, format => new, body => UserId},
                                SelfSigPkt,
                                #{tag => 14, format => new, body => SubPubBody},
                                BindSigPkt
                            ],
                            Armored = gpg_keys:encode_public(Packets),
                            %% The same checks as on import catch a subkey signing key
                            %% that does not match the subkey.
                            case import_public_bundle(Armored) of
                                {ok, #{subkeys := [_]}} ->
                                    {ok, Armored, #{
                                        primary_fpr => openpgp_fingerprint:v4_fingerprint(PrimaryPubBody),
                                        subkey_fpr => openpgp_fingerprint:v4_fingerprint(SubPubBody)
                                    }};
                                {ok, #{rejected_subkeys := [#{reason := Reason}]}} ->
                                    {error, {bad_subkey_binding, Reason}};
                                {error, _} = Err ->
                                    Err
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {{error, _} = Err, _, _} ->
            Err;
        {_, {error, _} = Err, _} ->
            Err;
        {_, _, {error, _} = Err} ->
            Err
    end.

%% A subkey that may sign binds the primary key back (0x19).
back_signature(SubkeyFlags, _SubkeyAny, _PrimaryPubBody, _SubPubBody, _Opts) when SubkeyFlags band 16#02 =:= 0 ->
    {ok, undefined};
back_signature(_SubkeyFlags, SubkeyAny, PrimaryPubBody, SubPubBody, Opts) ->
    case to_subkey_signing_key(SubkeyAny, Opts) of
        {ok, {SubAlg, SubPriv}} ->
            #{packet := #{body := Body}} =
                openpgp_sig:primary_key_binding(SubAlg, #{priv => SubPriv}, PrimaryPubBody, SubPubBody),
            {ok, Body};
        {error, _} = Err ->
            {error, {missing_subkey_signing_key, Err}}
    end.

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

parse_v4_sig_info(
    <<4:8, SigType:8, PkAlgId:8, HashAlgId:8, HashedLen:16/big-unsigned, Hashed:HashedLen/binary,
      UnhashedLen:16/big-unsigned, Unhashed:UnhashedLen/binary, _Hash16:2/binary, _Rest/binary>>
) ->
    {ok, #{sig_type => SigType, pk_alg => PkAlgId, hash_alg => HashAlgId, hashed_sub => Hashed, unhashed_sub => Unhashed}};
parse_v4_sig_info(_Other) ->
    {error, bad_signature_packet}.

subkey_flags_from_subpackets(Subpackets) when is_binary(Subpackets) ->
    case openpgp_detached_sig:sig_subpacket(27, Subpackets) of
        {ok, <<Flags:8, _/binary>>} -> Flags;
        _ -> undefined
    end.

%% Internal: build a v4 Public-Key packet body from OTP crypto pubkey formats.
pubkey_body({rsa, [E, N]}, Created) when is_binary(E), is_binary(N), is_integer(Created), Created >= 0 ->
    iolist_to_binary([<<4:8, Created:32/big-unsigned, 1:8>>, openpgp_mpi:encode_bin(N), openpgp_mpi:encode_bin(E)]);
pubkey_body({ed25519, Pub32}, Created) when is_binary(Pub32), byte_size(Pub32) =:= 32, is_integer(Created), Created >= 0 ->
    Oid = ed25519_oid(),
    PubOpaque = <<16#40, Pub32/binary>>,
    iolist_to_binary([
        <<4:8, Created:32/big-unsigned, 22:8>>,
        <<(byte_size(Oid)):8, Oid/binary>>,
        openpgp_mpi:encode_bin(PubOpaque)
    ]).

to_crypto_pub({rsa, [E, N]} = Pub) when is_binary(E), is_binary(N) ->
    {ok, Pub};
to_crypto_pub({ed25519, Pub32} = Pub) when is_binary(Pub32), byte_size(Pub32) =:= 32 ->
    {ok, Pub};
to_crypto_pub(#'RSAPublicKey'{modulus = N, publicExponent = E}) ->
    {ok, {rsa, [bin_u(E), bin_u(N)]}};
to_crypto_pub(#'RSAPrivateKey'{} = R) ->
    {ok, {rsa, [bin_u(R#'RSAPrivateKey'.publicExponent), bin_u(R#'RSAPrivateKey'.modulus)]}};
to_crypto_pub({#'ECPoint'{point = Pub0}, {namedCurve, Oid}}) ->
    case is_ed25519_curve(Oid) of
        true -> {ok, {ed25519, ed25519_pub32(Pub0)}};
        false -> {error, {unsupported_curve, Oid}}
    end;
to_crypto_pub(#'ECPrivateKey'{publicKey = #'ECPoint'{point = Pub0}, parameters = {namedCurve, Oid}}) ->
    case is_ed25519_curve(Oid) of
        true -> {ok, {ed25519, ed25519_pub32(Pub0)}};
        false -> {error, {unsupported_curve, Oid}}
    end;
to_crypto_pub({'ECPrivateKey', _Ver, _PrivField, {namedCurve, Oid}, PubField}) ->
    to_crypto_pub({#'ECPoint'{point = PubField}, {namedCurve, Oid}});
to_crypto_pub({'ECPrivateKey', _Ver, _PrivField, {namedCurve, Oid}, PubField, _Attrs}) ->
    to_crypto_pub({#'ECPoint'{point = PubField}, {namedCurve, Oid}});
to_crypto_pub(Other) ->
    {error, {unsupported_public_key, Other}}.

to_primary_signing_key(PrimaryAny, Opts) when is_map(Opts) ->
    case maps:find(signing_key, Opts) of
        {ok, Priv} ->
            to_primary_signing_key_from_priv(Priv);
        error ->
            % Try to derive from the primary key input itself (if it includes private material).
            to_primary_signing_key_from_priv(PrimaryAny)
    end.

to_primary_signing_key_from_priv(Priv) when is_list(Priv) ->
    % RSA crypto private key list
    {ok, {rsa, Priv}};
to_primary_signing_key_from_priv(Priv32) when is_binary(Priv32), byte_size(Priv32) =:= 32 ->
    % Ed25519 private key
    {ok, {ed25519, Priv32}};
to_primary_signing_key_from_priv(#'RSAPrivateKey'{} = R) ->
    case rsa_priv_record_to_crypto(R) of
        {ok, PrivCrypto} -> {ok, {rsa, PrivCrypto}};
        {error, _} = Err -> Err
    end;
% Handle both public_key record form and raw tuple variants for Ed25519 ECPrivateKey.
% (Records are tuples under the hood, so we prefer tuple matching here.)
to_primary_signing_key_from_priv({'ECPrivateKey', _Ver, PrivField, {namedCurve, Oid}, PubField} = _T) ->
    case is_ed25519_curve(Oid) of
        false -> {error, {unsupported_curve, Oid}};
        true ->
            case ed25519_from_ecprivate_tuple_fields(PrivField, PubField) of
                {ok, {_Pub32, Priv32}} when is_binary(Priv32), byte_size(Priv32) =:= 32 ->
                    {ok, {ed25519, Priv32}};
                {error, _} = Err ->
                    Err
            end
    end;
to_primary_signing_key_from_priv({'ECPrivateKey', _Ver, PrivField, {namedCurve, Oid}, PubField, _Attrs} = _T) ->
    to_primary_signing_key_from_priv({'ECPrivateKey', 1, PrivField, {namedCurve, Oid}, PubField});
to_primary_signing_key_from_priv(Other) ->
    {error, {bad_signing_key, Other}}.

to_subkey_signing_key(SubkeyAny, Opts) when is_map(Opts) ->
    case maps:find(subkey_signing_key, Opts) of
        {ok, Priv} ->
            to_primary_signing_key_from_priv(Priv);
        error ->
            to_primary_signing_key_from_priv(SubkeyAny)
    end.

subkey_flags_int(I) when is_integer(I), I >= 0, I =< 255 ->
    I;
subkey_flags_int(Bin) when is_binary(Bin), byte_size(Bin) >= 1 ->
    <<I:8, _/binary>> = Bin,
    I;
subkey_flags_int(Atoms) when is_list(Atoms) ->
    lists:foldl(fun subkey_flag_atom_bit/2, 0, Atoms);
subkey_flags_int(Other) ->
    error({bad_subkey_flags, Other}).

self_cert_opts(Opts) ->
    FlagsOpt =
        case maps:find(primary_key_flags, Opts) of
            error -> #{};
            {ok, Flags0} -> #{key_flags => primary_key_flags_int(Flags0)}
        end,
    case primary_expires_seconds(Opts) of
        undefined -> FlagsOpt;
        Exp -> FlagsOpt#{key_expiration => Exp}
    end.

primary_key_flags_int(Flags) ->
    subkey_flags_int(Flags).

primary_expires_seconds(Opts) ->
    case maps:find(primary_expires, Opts) of
        {ok, Exp} -> expiration_seconds(Exp);
        error ->
            case maps:find(expires, Opts) of
                {ok, Exp2} -> expiration_seconds(Exp2);
                error -> undefined
            end
    end.

subkey_expires_seconds(Opts) ->
    case maps:find(subkey_expires, Opts) of
        {ok, Exp} -> expiration_seconds(Exp);
        error -> undefined
    end.

expiration_seconds(Exp) when is_integer(Exp), Exp >= 0, Exp =< 16#FFFFFFFF ->
    Exp;
expiration_seconds(Other) ->
    error({bad_key_expiration, Other}).

subkey_flag_atom_bit(certify, Acc) ->
    Acc bor 16#01;
subkey_flag_atom_bit(sign, Acc) ->
    Acc bor 16#02;
subkey_flag_atom_bit(encrypt_communication, Acc) ->
    Acc bor 16#04;
subkey_flag_atom_bit(encrypt_storage, Acc) ->
    Acc bor 16#08;
subkey_flag_atom_bit(split, Acc) ->
    Acc bor 16#10;
subkey_flag_atom_bit(authentication, Acc) ->
    Acc bor 16#20;
subkey_flag_atom_bit(auth, Acc) ->
    Acc bor 16#20;
subkey_flag_atom_bit(Other, _Acc) ->
    error({bad_subkey_flag_atom, Other}).

public_key_body_info(<<4:8, Created:32/big-unsigned, AlgId:8, _/binary>> = Body) ->
    Alg =
        case AlgId of
            1 -> rsa;
            22 -> ed25519;
            _ -> unknown
        end,
    Fpr = openpgp_fingerprint:v4_fingerprint(Body),
    KeyId = openpgp_fingerprint:keyid_from_fingerprint(Fpr),
    {ok, #{created => Created, alg => Alg, fingerprint => Fpr, keyid => KeyId}};
public_key_body_info(_Body) ->
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
                            [{_Bd, D}, {_Bp, P}, {_Bq, Q}, {_Bu, _U}] = Mpis,
                            Dint = binary:decode_unsigned(D),
                            Pint = binary:decode_unsigned(P),
                            Qint = binary:decode_unsigned(Q),
                            Nint = binary:decode_unsigned(N),
                            if
                                (Chk band 16#FFFF) =/= Sum ->
                                    {error, bad_checksum};
                                Pint < 2; Qint < 2; Pint * Qint =/= Nint ->
                                    {error, bad_rsa_secret};
                                true ->
                                    DP = binary:encode_unsigned(Dint rem (Pint - 1)),
                                    DQ = binary:encode_unsigned(Dint rem (Qint - 1)),
                                    QInv = binary:encode_unsigned(modinv(Qint, Pint)),
                                    {ok, [E, N, strip_zeros(D), strip_zeros(P), strip_zeros(Q), DP, DQ, QInv]}
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
                {ok, {[{_Bits, Priv0}] = Mpis, After}} ->
                    case After of
                        <<Chk:16/big-unsigned>> ->
                            Sum = checksum16(openpgp_mpis_to_encoded(Mpis)),
                            case (Chk band 16#FFFF) =:= Sum of
                                true ->
                                    %% The MPI drops the scalar's leading zero octets.
                                    case strip_zeros(Priv0) of
                                        Priv when byte_size(Priv) =< 32 -> {ok, leftpad32(Priv)};
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

%% The checksum covers the MPIs as they were encoded.
openpgp_mpis_to_encoded(Mpis) ->
    iolist_to_binary([<<Bits:16/big-unsigned, V/binary>> || {Bits, V} <- Mpis]).

strip_zeros(<<0, Rest/binary>>) -> strip_zeros(Rest);
strip_zeros(Bin) -> Bin.

checksum16(Bin) ->
    checksum16(Bin, 0) band 16#FFFF.

checksum16(<<>>, Sum) ->
    Sum;
checksum16(<<Byte:8, Rest/binary>>, Sum) ->
    checksum16(Rest, Sum + Byte).

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
                            {P2, _} -> P2
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


