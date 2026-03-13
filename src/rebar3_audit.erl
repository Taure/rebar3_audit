-module(rebar3_audit).

-export([init/1]).

init(State) ->
    {ok, State1} = rebar3_audit_prv:init(State),
    {ok, State1}.
