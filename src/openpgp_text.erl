%%% @doc Helpers for OpenPGP "canonical text" processing and cleartext dash-escaping.
-module(openpgp_text).

-export([canonicalize_text/1, strip_trailing_whitespace/1, dash_escape/1, dash_unescape/1]).

%% @doc Canonicalize text for OpenPGP text signatures (sigtype 0x01).
%%
%% RFC 4880 5.2.1: a canonical text document has its line endings converted
%% to CRLF, and nothing else. Trailing whitespace is left alone; stripping it
%% belongs to the cleartext signature framework only (see
%% `strip_trailing_whitespace/1`), and doing it here made detached text
%% signatures disagree with GnuPG whenever a line ended in a space or tab.
-spec canonicalize_text(iodata() | binary()) -> binary().
canonicalize_text(Text0) ->
    Text = iolist_to_binary(Text0),
    Lines0 = binary:split(Text, <<"\n">>, [global]),
    Lines1 = [trim_cr(L) || L <- Lines0],
    iolist_to_binary(join_crlf(Lines1)).

%% @doc Remove trailing spaces and tabs from every line (RFC 4880 7.1).
%%
%% Used by the cleartext signature framework, where the signed text is the
%% cleartext with trailing whitespace removed from each line.
-spec strip_trailing_whitespace(iodata() | binary()) -> binary().
strip_trailing_whitespace(Text0) ->
    Text = iolist_to_binary(Text0),
    Lines0 = binary:split(Text, <<"\n">>, [global]),
    iolist_to_binary(join_lf([rstrip_ws(trim_cr(L)) || L <- Lines0])).

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


