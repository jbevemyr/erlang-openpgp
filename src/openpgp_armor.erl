%%% @doc OpenPGP ASCII Armor encode/decode (RFC 4880).
%%%
%%% Supports any BEGIN/END type; for keys you'll typically see:
%%% - "PGP PUBLIC KEY BLOCK"
%%% - "PGP PRIVATE KEY BLOCK"
-module(openpgp_armor).

-export([decode/1, encode/2, encode/3]).

-type armor_type() :: binary().
-type armor_headers() :: [{binary(), binary()}].
-type decoded() :: #{
    type := armor_type(),
    headers := armor_headers(),
    data := binary()
}.

-spec decode(iodata() | binary()) -> {ok, decoded()} | {error, term()}.
decode(Input0) ->
    Input = iolist_to_binary(Input0),
    Lines = split_lines(Input),
    case find_begin(Lines) of
        {ok, Type, AfterBegin} ->
            {Headers, AfterHeaders} = parse_headers(AfterBegin, []),
            {B64Lines, _AfterEnd} = take_until_end(AfterHeaders, Type, []),
            case extract_crc_line(B64Lines) of
                {PayloadLines, undefined} ->
                    decode_payload(Type, Headers, PayloadLines, undefined);
                {PayloadLines, CrcLine} ->
                    decode_payload(Type, Headers, PayloadLines, CrcLine)
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
            ({K0, V0}) ->
                {iolist_to_binary(K0), iolist_to_binary(V0)};
            (Other) ->
                error({bad_header, Other})
        end,
        H
    ).

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
    case parse_begin(Line) of
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
    Line =:= <<"-----END ", Type/binary, "-----">>.

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

take_until_end([], _Type, Acc) ->
    {lists:reverse(Acc), []};
take_until_end([Line | Rest], Type, Acc) ->
    case parse_end(Line, Type) of
        true -> {lists:reverse(Acc), Rest};
        false -> take_until_end(Rest, Type, [Line | Acc])
    end.

extract_crc_line(Lines) ->
    % CRC line is "=xxxx" near end; we accept it as the last non-empty line.
    NonEmpty = [L || L <- Lines, L =/= <<>>],
    case lists:reverse(NonEmpty) of
        [Last | RevRest] when byte_size(Last) >= 2 ->
            case Last of
                <<"=", _/binary>> ->
                    Payload = lists:reverse(RevRest),
                    {Payload, Last};
                _ ->
                    {Lines, undefined}
            end;
        _ ->
            {Lines, undefined}
    end.

decode_payload(Type, Headers, PayloadLines, CrcLine) ->
    PayloadBin = iolist_to_binary(PayloadLines),
    % Strip all whitespace just in case (some armor wraps with spaces).
    PayloadB64 = strip_ws(PayloadBin),
    case safe_b64decode(PayloadB64) of
        {ok, Data} ->
            case verify_crc(Data, CrcLine) of
                ok ->
                    {ok, #{type => Type, headers => Headers, data => Data}};
                {error, _} = Err ->
                    Err
            end;
        {error, Reason} ->
            {error, {bad_base64, Reason}}
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

verify_crc(_Data, undefined) ->
    ok;
verify_crc(Data, <<"=", CrcB64/binary>>) ->
    case safe_b64decode(CrcB64) of
        {ok, <<Crc:24>>} ->
            Crc2 = openpgp_crc24:crc24(Data),
            case Crc =:= Crc2 of
                true -> ok;
                false -> {error, {crc_mismatch, Crc, Crc2}}
            end;
        {ok, Other} ->
            {error, {bad_crc_length, byte_size(Other)}};
        {error, Reason} ->
            {error, {bad_crc_base64, Reason}}
    end;
verify_crc(_Data, Other) ->
    {error, {bad_crc_line, Other}}.

wrap64(B64) when is_binary(B64) ->
    wrap64(B64, []).

wrap64(<<>>, Acc) ->
    iolist_to_binary(lists:reverse(Acc));
wrap64(B64, Acc) when byte_size(B64) =< 64 ->
    iolist_to_binary(lists:reverse([B64 | Acc]));
wrap64(B64, Acc) ->
    <<Line:64/binary, Rest/binary>> = B64,
    wrap64(Rest, [<<"\n">>, Line | Acc]).


