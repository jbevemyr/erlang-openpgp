%%% @doc OpenPGP MPI encode/decode helpers (RFC 4880).
-module(openpgp_mpi).

-export([encode_int/1, encode_bin/1, decode_one/1]).

-spec encode_int(non_neg_integer()) -> binary().
encode_int(Int) when is_integer(Int), Int >= 0 ->
    encode_bin(int_to_bin(Int)).

-spec encode_bin(binary()) -> binary().
encode_bin(Bin0) when is_binary(Bin0) ->
    Bin = strip_leading_zeros(Bin0),
    Bits = bitlen(Bin),
    <<Bits:16/big-unsigned, Bin/binary>>.

-spec decode_one(binary()) -> {ok, {non_neg_integer(), binary(), binary()}} | {error, term()}.
decode_one(<<Bits:16/big-unsigned, Rest/binary>>) ->
    Bytes = (Bits + 7) div 8,
    case Rest of
        <<Val:Bytes/binary, Tail/binary>> ->
            {ok, {Bits, Val, Tail}};
        _ ->
            {error, truncated}
    end;
decode_one(_) ->
    {error, truncated}.

%% Internal

strip_leading_zeros(<<0, Rest/binary>>) -> strip_leading_zeros(Rest);
strip_leading_zeros(Bin) -> Bin.

int_to_bin(0) ->
    <<>>;
int_to_bin(Int) ->
    binary:encode_unsigned(Int).

bitlen(<<>>) ->
    0;
bitlen(Bin) ->
    <<First:8, _/binary>> = Bin,
    Leading = leading_zeros8(First),
    byte_size(Bin) * 8 - Leading.

leading_zeros8(0) -> 8;
leading_zeros8(N) when N < 2 -> 7;
leading_zeros8(N) when N < 4 -> 6;
leading_zeros8(N) when N < 8 -> 5;
leading_zeros8(N) when N < 16 -> 4;
leading_zeros8(N) when N < 32 -> 3;
leading_zeros8(N) when N < 64 -> 2;
leading_zeros8(N) when N < 128 -> 1;
leading_zeros8(_) -> 0.


