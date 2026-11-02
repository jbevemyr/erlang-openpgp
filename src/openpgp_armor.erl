%%% @doc OpenPGP ASCII Armor encode/decode (RFC 4880).
%%%
%%% Supports any BEGIN/END type; for keys you'll typically see:
%%% - "PGP PUBLIC KEY BLOCK"
%%% - "PGP PRIVATE KEY BLOCK"
-module(openpgp_armor).

-export([decode/1, decode_all/1, encode/2, encode/3]).

-type armor_type() :: binary().
-type armor_headers() :: [{binary(), binary()}].
-type decoded() :: #{
    type := armor_type(),
    headers := armor_headers(),
    data := binary()
}.

%% @doc Decode the first armor block in the input.
%%
%% The CRC line is optional. When present it is checked, as GnuPG does,
%% although RFC 9580 6.1 says not to: it is the only thing that catches a
%% corrupted block whose packets still parse.
-spec decode(iodata() | binary()) -> {ok, decoded()} | {error, term()}.
decode(Input) ->
    case decode_block(split_lines(iolist_to_binary(Input))) of
        {ok, Decoded, _AfterEnd} -> {ok, Decoded};
        {error, _} = Err -> Err
    end.

%% @doc Decode every armor block in the input, in order.
-spec decode_all(iodata() | binary()) -> {ok, [decoded()]} | {error, term()}.
decode_all(Input) ->
    case decode_block(split_lines(iolist_to_binary(Input))) of
        {ok, Decoded, AfterEnd} -> decode_rest(AfterEnd, [Decoded]);
        {error, _} = Err -> Err
    end.

decode_rest(Lines, Acc) ->
    case decode_block(Lines) of
        {ok, Decoded, AfterEnd} -> decode_rest(AfterEnd, [Decoded | Acc]);
        {error, no_begin_line} -> {ok, lists:reverse(Acc)};
        {error, _} = Err -> Err
    end.

decode_block(Lines) ->
    case find_begin(Lines) of
        {ok, Type, AfterBegin} ->
            {Headers, AfterHeaders} = parse_headers(AfterBegin, []),
            case take_until_end(AfterHeaders, Type, []) of
                {ok, B64Lines, AfterEnd} ->
                    {PayloadLines, CrcLine} = split_crc_line(B64Lines),
                    case decode_payload(Type, Headers, PayloadLines, CrcLine) of
                        {ok, Decoded} -> {ok, Decoded, AfterEnd};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        error ->
            {error, no_begin_line}
    end.

-spec encode(armor_type() | iodata(), binary()) -> binary().
encode(Type0, Data) ->
    encode(Type0, [], Data).

-spec encode(armor_type() | iodata(), armor_headers(), binary()) -> binary().
encode(Type0, Headers0, Data) when is_binary(Data) ->
    Type = iolist_to_binary(Type0),
    case has_line_break(Type) of
        true -> error({bad_armor_type, Type});
        false -> ok
    end,
    Headers = normalize_headers(Headers0),
    B64 = base64:encode(Data),
    B64Wrapped = wrap64(B64),
    CrcInt = openpgp_crc24:crc24(Data),
    CrcBin = <<CrcInt:24>>,
    CrcB64 = base64:encode(CrcBin),
    Begin = <<"-----BEGIN ", Type/binary, "-----\n">>,
    HeaderBin = headers_to_iolist(Headers),
    Sep = <<"\n">>,
    Body = iolist_to_binary([B64Wrapped, "\n=", CrcB64, "\n"]),
    End = <<"-----END ", Type/binary, "-----\n">>,
    iolist_to_binary([Begin, HeaderBin, Sep, Body, End]).

%% Internal

normalize_headers(H) when is_list(H) ->
    lists:map(
        fun
            ({K0, V0} = H0) ->
                K = iolist_to_binary(K0),
                V = iolist_to_binary(V0),
                case
                    K =:= <<>> orelse binary:match(K, <<":">>) =/= nomatch orelse
                        has_line_break(K) orelse has_line_break(V)
                of
                    true -> error({bad_header, H0});
                    false -> {K, V}
                end;
            (Other) ->
                error({bad_header, Other})
        end,
        H
    ).

has_line_break(Bin) ->
    binary:match(Bin, [<<"\r">>, <<"\n">>]) =/= nomatch.

headers_to_iolist([]) ->
    <<>>;
headers_to_iolist(Headers) ->
    lists:map(fun({K, V}) -> <<K/binary, ": ", V/binary, "\n">> end, Headers).

split_lines(Bin) ->
    % Keep it simple: split on \n and trim possible \r.
    Raw = binary:split(Bin, <<"\n">>, [global]),
    [trim_cr(L) || L <- Raw].

trim_cr(Bin) when is_binary(Bin) ->
    case byte_size(Bin) of
        0 ->
            Bin;
        N ->
            case binary:at(Bin, N - 1) of
                $\r -> binary:part(Bin, 0, N - 1);
                _ -> Bin
            end
    end.

find_begin([]) ->
    error;
find_begin([Line | Rest]) ->
    case parse_begin(rstrip_ws(Line)) of
        {ok, Type} -> {ok, Type, Rest};
        error -> find_begin(Rest)
    end.

parse_begin(Line) ->
    Prefix = <<"-----BEGIN ">>,
    Suffix = <<"-----">>,
    case {binary:match(Line, Prefix), binary:match(Line, Suffix)} of
        {{0, _}, _} ->
            % Expect: -----BEGIN <TYPE>-----
            case binary:split(Line, Prefix, [global]) of
                [<<>>, Tail] ->
                    case binary:split(Tail, Suffix, [global]) of
                        [Type, <<>>] when byte_size(Type) > 0 ->
                            {ok, Type};
                        _ ->
                            error
                    end;
                _ ->
                    error
            end;
        _ ->
            error
    end.

parse_end(Line, Type) ->
    rstrip_ws(Line) =:= <<"-----END ", Type/binary, "-----">>.

rstrip_ws(<<>>) ->
    <<>>;
rstrip_ws(Bin) ->
    N = byte_size(Bin) - 1,
    case binary:at(Bin, N) of
        C when C =:= $\s; C =:= $\t; C =:= $\r -> rstrip_ws(binary:part(Bin, 0, N));
        _ -> Bin
    end.

parse_headers([], Acc) ->
    {lists:reverse(Acc), []};
parse_headers([<<>> | Rest], Acc) ->
    {lists:reverse(Acc), Rest};
parse_headers([Line | Rest], Acc) ->
    case binary:match(Line, <<": ">>) of
        {Pos, 2} when Pos > 0 ->
            K = binary:part(Line, 0, Pos),
            V = binary:part(Line, Pos + 2, byte_size(Line) - (Pos + 2)),
            parse_headers(Rest, [{K, V} | Acc]);
        _ ->
            % If no header separator, armor allows empty header section; treat this as start of data.
            {lists:reverse(Acc), [Line | Rest]}
    end.

take_until_end([], _Type, _Acc) ->
    {error, no_end_line};
take_until_end([Line | Rest], Type, Acc) ->
    case parse_end(Line, Type) of
        true -> {ok, lists:reverse(Acc), Rest};
        false -> take_until_end(Rest, Type, [Line | Acc])
    end.

%% The CRC line, if any, is the last non-empty line and starts with "=",
%% which no base64 data line can.
split_crc_line(Lines) ->
    NonEmpty = [L || L <- Lines, L =/= <<>>],
    case lists:reverse(NonEmpty) of
        [<<"=", _/binary>> = Crc | RevRest] -> {lists:reverse(RevRest), Crc};
        _ -> {Lines, undefined}
    end.

decode_payload(Type, Headers, PayloadLines, CrcLine) ->
    PayloadBin = iolist_to_binary(PayloadLines),
    % Strip all whitespace just in case (some armor wraps with spaces).
    PayloadB64 = strip_ws(PayloadBin),
    case safe_b64decode(PayloadB64) of
        {ok, Data} ->
            case verify_crc(Data, CrcLine) of
                ok -> {ok, #{type => Type, headers => Headers, data => Data}};
                {error, _} = Err -> Err
            end;
        {error, Reason} ->
            {error, {bad_base64, Reason}}
    end.

verify_crc(_Data, undefined) ->
    ok;
verify_crc(Data, <<"=", CrcB64/binary>>) ->
    case safe_b64decode(CrcB64) of
        {ok, <<Crc:24>>} ->
            case openpgp_crc24:crc24(Data) of
                Crc -> ok;
                Crc2 -> {error, {crc_mismatch, Crc, Crc2}}
            end;
        {ok, Other} ->
            {error, {bad_crc_length, byte_size(Other)}};
        {error, Reason} ->
            {error, {bad_crc_base64, Reason}}
    end.

strip_ws(Bin) ->
    strip_ws(Bin, <<>>).

strip_ws(<<>>, Acc) ->
    Acc;
strip_ws(<<C, Rest/binary>>, Acc)
  when C =:= $\s; C =:= $\t; C =:= $\r; C =:= $\n ->
    strip_ws(Rest, Acc);
strip_ws(<<C, Rest/binary>>, Acc) ->
    strip_ws(Rest, <<Acc/binary, C>>).

safe_b64decode(B64) ->
    try {ok, base64:decode(B64)} catch _:R -> {error, R} end.

wrap64(B64) when is_binary(B64) ->
    wrap64(B64, []).

wrap64(<<>>, Acc) ->
    iolist_to_binary(lists:reverse(Acc));
wrap64(B64, Acc) when byte_size(B64) =< 64 ->
    iolist_to_binary(lists:reverse([B64 | Acc]));
wrap64(B64, Acc) ->
    <<Line:64/binary, Rest/binary>> = B64,
    wrap64(Rest, [<<"\n">>, Line | Acc]).


