%%% @doc Minimal supervisor for the erlang_openpgp application.
-module(erlang_openpgp_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec init(term()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    % Library-style application: no long-running children by default.
    {ok, {#{strategy => one_for_one, intensity => 1, period => 5}, []}}.


