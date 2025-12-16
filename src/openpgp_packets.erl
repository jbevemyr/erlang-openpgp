%%% @doc OpenPGP packet decoding/encoding (RFC 4880).
%%%
%%% This focuses on packet framing (headers + bodies). It does not interpret
%%% packet bodies beyond returning them as binaries.
-module(openpgp_packets).

-export([decode/1, encode/1]).
-export_type([packet/0]).

-type packet() :: #{
    tag := non_neg_integer(),
    format := old | new,
    body := binary()
}.

-spec decode(binary() | iodata()) -> {ok, [packet()]} | {error, term()}.
decode(Bin0) ->
    Bin = iolist_to_binary(Bin0),
    decode_packets(Bin, []).

-spec encode([packet()]) -> binary().
encode(Packets) ->
    iolist_to_binary([encode_packet(P) || P <- Packets]).

%% Internal decode

decode_packets(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_packets(<<First:8, _/binary>> = Bin, Acc) ->
    case (First band 16#80) =:= 16#80 of
        false ->
            {error, {not_a_packet, First}};
        true ->
            case (First band 16#40) =:= 16#40 of
                true ->
                    decode_new_packet(Bin, Acc);
                false ->
                    decode_old_packet(Bin, Acc)
            end
    end.

decode_old_packet(<<Hdr:8, Rest/binary>>, Acc) ->
    Tag = (Hdr band 16#3C) bsr 2,
    LenType = Hdr band 16#03,
    case LenType of
        0 ->
            case Rest of
                <<Len:8, Body:Len/binary, Tail/binary>> ->
                    decode_packets(Tail, [#{tag => Tag, format => old, body => Body} | Acc]);
                _ ->
                    {error, truncated}
            end;
        1 ->
            case Rest of
                <<Len:16/big-unsigned, Body:Len/binary, Tail/binary>> ->
                    decode_packets(Tail, [#{tag => Tag, format => old, body => Body} | Acc]);
                _ ->
                    {error, truncated}
            end;
        2 ->
            case Rest of
                <<Len:32/big-unsigned, Body:Len/binary, Tail/binary>> ->
                    decode_packets(Tail, [#{tag => Tag, format => old, body => Body} | Acc]);
                _ ->
                    {error, truncated}
            end;
        3 ->
            % Indeterminate length: body extends to EOF.
            decode_packets(<<>>, [#{tag => Tag, format => old, body => Rest} | Acc])
    end.

decode_new_packet(<<Hdr:8, Rest/binary>>, Acc) ->
    Tag = Hdr band 16#3F,
    case decode_new_length(Rest) of
        {ok, {Len, AfterLen}} when is_integer(Len) ->
            case AfterLen of
                <<Body:Len/binary, Tail/binary>> ->
                    decode_packets(Tail, [#{tag => Tag, format => new, body => Body} | Acc]);
                _ ->
                    {error, truncated}
            end;
        {ok, {partial, Segs, Tail0}} ->
            case take_partial_segments(Tail0, Segs, <<>>) of
                {ok, {Body, Tail}} ->
                    decode_packets(Tail, [#{tag => Tag, format => new, body => Body} | Acc]);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

decode_new_length(<<First:8, Rest/binary>>) when First < 192 ->
    {ok, {First, Rest}};
decode_new_length(<<First:8, Second:8, Rest/binary>>) when First >= 192, First =< 223 ->
    Len = ((First - 192) bsl 8) + Second + 192,
    {ok, {Len, Rest}};
decode_new_length(<<255:8, Len:32/big-unsigned, Rest/binary>>) ->
    {ok, {Len, Rest}};
decode_new_length(<<First:8, Rest/binary>>) when First >= 224, First =< 254 ->
    % Partial body length. Segment length is 1 << (First & 0x1F)
    Pow = First band 16#1F,
    SegLen = 1 bsl Pow,
    {ok, {partial, [SegLen], Rest}};
decode_new_length(<<>>) ->
    {error, truncated}.

take_partial_segments(Bin, SegLens, Acc) ->
    case SegLens of
        [SegLen] ->
            case Bin of
                <<Seg:SegLen/binary, Rest/binary>> ->
                    % Next length octet follows (could be another partial or final)
                    case decode_new_length(Rest) of
                        {ok, {partial, [NextSegLen], AfterLen}} ->
                            take_partial_segments(AfterLen, [NextSegLen], <<Acc/binary, Seg/binary>>);
                        {ok, {Len, AfterLen}} when is_integer(Len) ->
                            case AfterLen of
                                <<Final:Len/binary, Tail/binary>> ->
                                    {ok, {<<Acc/binary, Seg/binary, Final/binary>>, Tail}};
                                _ ->
                                    {error, truncated}
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                _ ->
                    {error, truncated}
            end
    end.

%% Internal encode (always uses new-format headers with definite lengths)

encode_packet(#{tag := Tag, body := Body}) when is_integer(Tag), Tag >= 0, Tag =< 63, is_binary(Body) ->
    Hdr = 16#C0 bor Tag,
    LenEnc = encode_new_length(byte_size(Body)),
    [<<Hdr:8>>, LenEnc, Body].

encode_new_length(Len) when Len < 192 ->
    <<Len:8>>;
encode_new_length(Len) when Len =< 8383 ->
    Len2 = Len - 192,
    First = (Len2 bsr 8) + 192,
    Second = Len2 band 16#FF,
    <<First:8, Second:8>>;
encode_new_length(Len) ->
    <<255:8, Len:32/big-unsigned>>.


