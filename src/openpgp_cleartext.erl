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
    hash => sha256 | sha512,
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
    HashHdr =
        case Hash of
            sha256 -> <<"SHA256">>;
            sha512 -> <<"SHA512">>
        end,
    % Dash-escape for transport; signature is computed over unescaped text.
    % Important: In the cleartext signature framework, the signed text is the
    % cleartext body *without* the line ending that precedes the signature block.
    TextForSig = drop_trailing_newline(Text),
    Escaped = openpgp_text:dash_escape(Text),
    {ok, SigArmored} =
        openpgp_detached_sig:sign(
            TextForSig,
            Key,
            Opts#{hash => Hash, sig_type => 16#01}
        ),
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
    {ok,
        iolist_to_binary([
            <<"-----BEGIN PGP SIGNED MESSAGE-----\n">>,
            <<"Hash: ", HashHdr/binary, "\n">>,
            <<"\n">>,
            EscapedNL,
            SigArmored
        ])}.

%% @doc Verify a clearsigned message with a public key.
-spec verify(iodata() | binary(), pubkey()) -> ok | {error, term()}.
verify(Clearsigned0, PubKey) ->
    case parse(Clearsigned0) of
        {ok, #{text := Text, signature := Sig}} ->
            openpgp_detached_sig:verify(Text, Sig, PubKey);
        {error, _} = Err ->
            Err
    end.

%% @doc Parse a clearsigned message into `{text, signature}`.
-spec parse(iodata() | binary()) -> {ok, #{text := binary(), signature := binary()}} | {error, term()}.
parse(Clearsigned0) ->
    Bin = iolist_to_binary(Clearsigned0),
    Lines = binary:split(Bin, <<"\n">>, [global]),
    case drop_until(Lines, <<"-----BEGIN PGP SIGNED MESSAGE-----">>) of
        {ok, AfterBegin} ->
            {Headers, AfterHeaders} = take_until_blank(AfterBegin, []),
            case Headers of
                _ ->
                    ok
            end,
            {TextLines, AfterText} = take_until(AfterHeaders, <<"-----BEGIN PGP SIGNATURE-----">>, []),
            % Reconstruct the signature block (from BEGIN PGP SIGNATURE to END).
            SigLines = [<<"-----BEGIN PGP SIGNATURE-----">> | AfterText],
            SigBin = iolist_to_binary(join_lf([trim_cr(L) || L <- SigLines])),
            Unescaped = openpgp_text:dash_unescape(iolist_to_binary(join_lf([trim_cr(L) || L <- TextLines]))),
            {ok, #{text => Unescaped, signature => SigBin}};
        error ->
            {error, not_clearsigned}
    end.

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


