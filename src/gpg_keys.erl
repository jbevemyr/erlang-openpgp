%%% @doc Import/export OpenPGP (GPG) key blocks without invoking `gpg`.
%%%
%%% "Import" here means decoding a PGP public/private key block (ASCII Armor or
%%% raw packets) into OpenPGP packets. "Export" means encoding packet binaries
%%% back to an armored key block.
%%%
%%% This module covers *format handling* (RFC 4880). It does not manage keyrings,
%%% perform crypto, or validate signatures.
-module(gpg_keys).

-export([
    decode/1,
    decode_packets/1,
    encode_public/1,
    encode_private/1,
    encode_packets/2
]).

-type packet() :: openpgp_packets:packet().

%% @doc Decode an ASCII-armored key block or raw OpenPGP packets.
%%
%% Returns `{ok, #{armor => ... | undefined, packets => [..]}}`.
-spec decode(iodata() | binary()) ->
    {ok, #{armor := map() | undefined, packets := [packet()]}} | {error, term()}.
decode(Input0) ->
    Input = iolist_to_binary(Input0),
    case is_armored(Input) of
        true ->
            case openpgp_armor:decode(Input) of
                {ok, Armor = #{data := Data}} ->
                    case openpgp_packets:decode(Data) of
                        {ok, Packets} -> {ok, #{armor => Armor, packets => Packets}};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        false ->
            case openpgp_packets:decode(Input) of
                {ok, Packets} -> {ok, #{armor => undefined, packets => Packets}};
                {error, _} = Err -> Err
            end
    end.

%% @doc Decode raw OpenPGP packets from binary.
-spec decode_packets(iodata() | binary()) -> {ok, [packet()]} | {error, term()}.
decode_packets(Bin) ->
    openpgp_packets:decode(Bin).

%% @doc Encode packets into an ASCII-armored public key block.
-spec encode_public([packet()] | binary() | iodata()) -> binary().
encode_public(PacketsOrBin) ->
    encode_keyblock(<<"PGP PUBLIC KEY BLOCK">>, PacketsOrBin).

%% @doc Encode packets into an ASCII-armored private key block.
-spec encode_private([packet()] | binary() | iodata()) -> binary().
encode_private(PacketsOrBin) ->
    encode_keyblock(<<"PGP PRIVATE KEY BLOCK">>, PacketsOrBin).

%% @doc Encode packets into an ASCII-armored block of given type.
-spec encode_packets(binary() | iodata(), [packet()] | binary() | iodata()) -> binary().
encode_packets(Type, PacketsOrBin) ->
    encode_keyblock(iolist_to_binary(Type), PacketsOrBin).

%% Internal

encode_keyblock(Type, PacketsOrBin) when is_list(PacketsOrBin) ->
    Bin = openpgp_packets:encode(PacketsOrBin),
    openpgp_armor:encode(Type, Bin);
encode_keyblock(Type, Bin) ->
    openpgp_armor:encode(Type, iolist_to_binary(Bin)).

is_armored(Bin) when is_binary(Bin) ->
    case binary:match(Bin, <<"-----BEGIN PGP ">>) of
        nomatch -> false;
        _ -> true
    end.


