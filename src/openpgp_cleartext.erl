%%% @doc OpenPGP cleartext signature framework (RFC 4880 §7).
%%%
%%% - Generate "BEGIN PGP SIGNED MESSAGE" blocks (clearsign)
%%% - Verify clearsigned messages
%%%
%%% Uses signature type 0x01 (canonical text document).
-module(openpgp_cleartext).

-export([sign/3, verify/2, parse/1]).

-type pubkey() :: {rsa, [binary()]} | {ed25519, binary()}.
-type privkey() :: {rsa, [binary()]} | {ed25519, binary()}.

-type opts() :: #{
    hash => sha224 | sha256 | sha384 | sha512,
    created => non_neg_integer(),
    issuer_fpr => binary()
}.

%% @doc Create a clearsigned message.
%%
%% `Text` is treated as text; signature is over canonicalized text (CRLF, strip trailing WS).
%% Output includes dash-escaped text and an ASCII-armored PGP SIGNATURE.
-spec sign(iodata() | binary(), privkey(), opts()) -> {ok, binary()} | {error, term()}.
sign(Text0, Key, Opts) ->
    Text = iolist_to_binary(Text0),
    Hash = maps:get(hash, Opts, sha512),
    % Dash-escape for transport; signature is computed over unescaped text.
    % In the cleartext signature framework the signed text has trailing
    % whitespace removed from every line (RFC 4880 7.1) and excludes the line
    % ending that precedes the signature block.
    TextForSig = drop_trailing_newline(openpgp_text:strip_trailing_whitespace(Text)),
    case hash_name(Hash) of
        {ok, HashHdr} ->
            case openpgp_detached_sig:sign(TextForSig, Key, Opts#{hash => Hash, sig_type => 16#01}) of
                {ok, SigArmored} ->
                    {ok, frame(openpgp_text:dash_escape(Text), HashHdr, SigArmored)};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

frame(Escaped, HashHdr, SigArmored) ->
    % Ensure there is a newline before signature separator.
    EscapedNL =
        case byte_size(Escaped) of
            0 -> <<"\n">>;
            N ->
                case binary:at(Escaped, N - 1) of
                    $\n -> Escaped;
                    _ -> <<Escaped/binary, "\n">>
                end
        end,
    iolist_to_binary([
        <<"-----BEGIN PGP SIGNED MESSAGE-----\n">>,
        <<"Hash: ", HashHdr/binary, "\n">>,
        <<"\n">>,
        EscapedNL,
        SigArmored
    ]).

%% @doc Verify a clearsigned message with a public key.
%%
%% When the message has `Hash` armor headers, every signature in it must use
%% one of the listed hash algorithms. Without them any hash is accepted
%% (RFC 9580 7.1).
-spec verify(iodata() | binary(), pubkey()) -> ok | {error, term()}.
verify(Clearsigned0, PubKey) ->
    case parse(Clearsigned0) of
        {ok, #{text := Text, signature := Sig, hashes := Hashes}} ->
            case check_hashes(Sig, Hashes) of
                ok ->
                    openpgp_detached_sig:verify(
                        openpgp_text:strip_trailing_whitespace(Text),
                        Sig,
                        PubKey,
                        #{sig_type => 16#01}
                    );
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Parse a clearsigned message into its text, signature block and the
%% hash names from its `Hash` armor headers (`undefined` when there are none).
-spec parse(iodata() | binary()) ->
    {ok, #{text := binary(), signature := binary(), hashes := [binary()] | undefined}}
    | {error, term()}.
parse(Clearsigned0) ->
    Bin = iolist_to_binary(Clearsigned0),
    Lines = binary:split(Bin, <<"\n">>, [global]),
    case drop_until(Lines, <<"-----BEGIN PGP SIGNED MESSAGE-----">>) of
        {ok, AfterBegin} ->
            {Headers, AfterHeaders} = take_until_blank(AfterBegin, []),
            {TextLines, AfterText} = take_until(AfterHeaders, <<"-----BEGIN PGP SIGNATURE-----">>, []),
            % Reconstruct the signature block (from BEGIN PGP SIGNATURE to END).
            SigLines = [<<"-----BEGIN PGP SIGNATURE-----">> | AfterText],
            SigBin = iolist_to_binary(join_lf([trim_cr(L) || L <- SigLines])),
            case parse_hash_headers(Headers, []) of
                {ok, Hashes} ->
                    case openpgp_text:dash_unescape(join_lf([trim_cr(L) || L <- TextLines])) of
                        {ok, Unescaped} ->
                            {ok, #{text => Unescaped, signature => SigBin, hashes => Hashes}};
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        error ->
            {error, not_clearsigned}
    end.

parse_hash_headers([], []) ->
    {ok, undefined};
parse_hash_headers([], Acc) ->
    {ok, lists:append(lists:reverse(Acc))};
parse_hash_headers([<<"Hash: ", Value/binary>> | Rest], Acc) ->
    Names = [string:trim(N, both, " \t") || N <- binary:split(Value, <<",">>, [global])],
    case [N || N <- Names, hash_id(N) =:= error] of
        [] -> parse_hash_headers(Rest, [Names | Acc]);
        [Unknown | _] -> {error, {unknown_hash, Unknown}}
    end;
parse_hash_headers([Line | _], _Acc) ->
    {error, {bad_armor_header, Line}}.

check_hashes(_Sig, undefined) ->
    ok;
check_hashes(Sig, Hashes) ->
    Allowed = [Id || N <- Hashes, {ok, Id} <- [hash_id(N)]],
    case [Id || Id <- sig_hash_algs(Sig), not lists:member(Id, Allowed)] of
        [] -> ok;
        [Id | _] -> {error, {hash_not_in_header, Id}}
    end.

%% A malformed signature block yields no hash algorithms here; the
%% subsequent verification reports it.
sig_hash_algs(Sig) ->
    case openpgp_armor:decode(Sig) of
        {ok, #{data := Data}} ->
            case openpgp_packets:decode(Data) of
                {ok, Packets} ->
                    [
                        HashAlg
                     || #{tag := 2} = P <- Packets,
                        {ok, #{hash_alg := HashAlg}} <- [
                            openpgp_detached_sig:parse_signature(openpgp_packets:encode([P]))
                        ]
                    ];
                {error, _} ->
                    []
            end;
        {error, _} ->
            []
    end.

hash_id(<<"MD5">>) -> {ok, 1};
hash_id(<<"SHA1">>) -> {ok, 2};
hash_id(<<"RIPEMD160">>) -> {ok, 3};
hash_id(<<"SHA256">>) -> {ok, 8};
hash_id(<<"SHA384">>) -> {ok, 9};
hash_id(<<"SHA512">>) -> {ok, 10};
hash_id(<<"SHA224">>) -> {ok, 11};
hash_id(<<"SHA3-256">>) -> {ok, 12};
hash_id(<<"SHA3-512">>) -> {ok, 14};
hash_id(_) -> error.

hash_name(sha224) -> {ok, <<"SHA224">>};
hash_name(sha256) -> {ok, <<"SHA256">>};
hash_name(sha384) -> {ok, <<"SHA384">>};
hash_name(sha512) -> {ok, <<"SHA512">>};
hash_name(Other) -> {error, {unsupported_hash, Other}}.

%% Internal parsing helpers

trim_cr(Bin) ->
    case byte_size(Bin) of
        0 -> Bin;
        N ->
            case binary:at(Bin, N - 1) of
                $\r -> binary:part(Bin, 0, N - 1);
                _ -> Bin
            end
    end.

drop_until([], _Needle) ->
    error;
drop_until([L | Rest], Needle) ->
    case trim_cr(L) =:= Needle of
        true -> {ok, Rest};
        false -> drop_until(Rest, Needle)
    end.

take_until_blank([], Acc) ->
    {lists:reverse(Acc), []};
take_until_blank([L | Rest], Acc) ->
    case trim_cr(L) of
        <<>> -> {lists:reverse(Acc), Rest};
        X -> take_until_blank(Rest, [X | Acc])
    end.

take_until([], _Needle, Acc) ->
    {lists:reverse(Acc), []};
take_until([L | Rest], Needle, Acc) ->
    case trim_cr(L) =:= Needle of
        true -> {lists:reverse(Acc), Rest};
        false -> take_until(Rest, Needle, [L | Acc])
    end.

join_lf([]) -> [];
join_lf([Last]) -> [Last];
join_lf([H | T]) -> [H, <<"\n">> | join_lf(T)].

drop_trailing_newline(Bin) when is_binary(Bin) ->
    case byte_size(Bin) of
        0 ->
            Bin;
        N ->
            case binary:at(Bin, N - 1) of
                $\n ->
                    Bin2 = binary:part(Bin, 0, N - 1),
                    case byte_size(Bin2) of
                        0 -> Bin2;
                        N2 ->
                            case binary:at(Bin2, N2 - 1) of
                                $\r -> binary:part(Bin2, 0, N2 - 1);
                                _ -> Bin2
                            end
                    end;
                _ ->
                    Bin
            end
    end.


