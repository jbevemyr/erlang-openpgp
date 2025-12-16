%%% @doc Helpers for OpenPGP "canonical text" processing and cleartext dash-escaping.
-module(openpgp_text).

-export([canonicalize_text/1, dash_escape/1, dash_unescape/1]).

%% @doc Canonicalize text for OpenPGP text signatures (sigtype 0x01).
%%
%% - Convert line endings to CRLF
%% - Strip trailing spaces/tabs at end of each line
%% - Preserve whether the input ended with a newline (i.e. final empty line)
-spec canonicalize_text(iodata() | binary()) -> binary().
canonicalize_text(Text0) ->
    Text = iolist_to_binary(Text0),
    Lines0 = binary:split(Text, <<"\n">>, [global]),
    Lines1 = [trim_cr(L) || L <- Lines0],
    Lines2 = [rstrip_ws(L) || L <- Lines1],
    iolist_to_binary(join_crlf(Lines2)).

trim_cr(Bin) when is_binary(Bin) ->
    case byte_size(Bin) of
        0 -> Bin;
        N ->
            case binary:at(Bin, N - 1) of
                $\r -> binary:part(Bin, 0, N - 1);
                _ -> Bin
            end
    end.

rstrip_ws(Bin) ->
    rstrip_ws(Bin, byte_size(Bin)).

rstrip_ws(Bin, 0) ->
    Bin;
rstrip_ws(Bin, N) ->
    case binary:at(Bin, N - 1) of
        $\s -> rstrip_ws(Bin, N - 1);
        $\t -> rstrip_ws(Bin, N - 1);
        _ -> binary:part(Bin, 0, N)
    end.

join_crlf([]) ->
    [];
join_crlf([Last]) ->
    [Last];
join_crlf([H | T]) ->
    [H, <<"\r\n">> | join_crlf(T)].

%% @doc Dash-escape lines for cleartext signatures.
%%
%% Per RFC 4880: prefix "- " to lines that begin with "-" or "From ".
-spec dash_escape(iodata() | binary()) -> binary().
dash_escape(Text0) ->
    Text = iolist_to_binary(Text0),
    Lines = binary:split(Text, <<"\n">>, [global]),
    Esc = [dash_escape_line(trim_cr(L)) || L <- Lines],
    iolist_to_binary(join_lf(Esc)).

dash_escape_line(<<"-", _/binary>> = L) -> <<"- ", L/binary>>;
dash_escape_line(<<"From ", _/binary>> = L) -> <<"- ", L/binary>>;
dash_escape_line(L) -> L.

%% @doc Undo dash-escaping in cleartext signatures ("- " prefix).
-spec dash_unescape(iodata() | binary()) -> binary().
dash_unescape(Text0) ->
    Text = iolist_to_binary(Text0),
    Lines = binary:split(Text, <<"\n">>, [global]),
    Un = [dash_unescape_line(trim_cr(L)) || L <- Lines],
    iolist_to_binary(join_lf(Un)).

dash_unescape_line(<<"- ", Rest/binary>>) -> Rest;
dash_unescape_line(L) -> L.

join_lf([]) -> [];
join_lf([Last]) -> [Last];
join_lf([H | T]) -> [H, <<"\n">> | join_lf(T)].


