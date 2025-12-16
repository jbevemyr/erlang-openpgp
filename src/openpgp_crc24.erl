%%% @doc CRC-24 as used by OpenPGP ASCII Armor (RFC 4880).
-module(openpgp_crc24).

-export([crc24/1]).

-spec crc24(iodata() | binary()) -> non_neg_integer().
crc24(Data0) ->
    Data = iolist_to_binary(Data0),
    crc24_bin(Data, 16#B704CE).

crc24_bin(<<>>, Crc) ->
    Crc band 16#FFFFFF;
crc24_bin(<<Byte:8, Rest/binary>>, Crc0) ->
    Crc1 = Crc0 bxor (Byte bsl 16),
    Crc2 = crc24_shift(8, Crc1),
    crc24_bin(Rest, Crc2).

crc24_shift(0, Crc) ->
    Crc;
crc24_shift(N, Crc0) when N > 0 ->
    Crc1 = Crc0 bsl 1,
    Crc2 =
        case (Crc1 band 16#1000000) =/= 0 of
            true -> Crc1 bxor 16#1864CFB;
            false -> Crc1
        end,
    crc24_shift(N - 1, Crc2).


