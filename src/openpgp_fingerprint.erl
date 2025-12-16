%%% @doc OpenPGP v4 fingerprint/keyid helpers (RFC 4880).
-module(openpgp_fingerprint).

-export([v4_fingerprint/1, keyid_from_fingerprint/1]).

-spec v4_fingerprint(binary()) -> binary().
v4_fingerprint(PublicKeyPacketBody) when is_binary(PublicKeyPacketBody) ->
    Len = byte_size(PublicKeyPacketBody),
    % 0x99 + 2-octet length + body
    crypto:hash(sha, <<16#99, Len:16/big-unsigned, PublicKeyPacketBody/binary>>).

-spec keyid_from_fingerprint(binary()) -> binary().
keyid_from_fingerprint(<<_Prefix:12/binary, Low64:8/binary>>) ->
    Low64;
keyid_from_fingerprint(Other) ->
    error({bad_fingerprint, byte_size(Other), Other}).


