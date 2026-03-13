-module(rebar3_audit_version).

-export([
    parse/1,
    compare/2,
    in_range/2
]).

-ifdef(TEST).
-export([parse_constraint/1]).
-endif.

-type version() :: {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
-type op() :: '<' | '<=' | '>' | '>=' | '='.
-type constraint() :: {op(), version()}.

-export_type([version/0]).

-spec parse(string() | binary()) -> {ok, version()} | error.
parse(Vsn) when is_binary(Vsn) ->
    parse(binary_to_list(Vsn));
parse(Vsn) when is_list(Vsn) ->
    Cleaned = strip_pre(string:trim(Vsn)),
    case string:tokens(Cleaned, ".") of
        [Major, Minor, Patch] ->
            try
                {ok, {
                    list_to_integer(Major),
                    list_to_integer(Minor),
                    list_to_integer(Patch)
                }}
            catch
                _:_ -> error
            end;
        [Major, Minor] ->
            try
                {ok, {list_to_integer(Major), list_to_integer(Minor), 0}}
            catch
                _:_ -> error
            end;
        _ ->
            error
    end.

-spec compare(version(), version()) -> lt | eq | gt.
compare(V, V) -> eq;
compare({A1, _, _}, {A2, _, _}) when A1 < A2 -> lt;
compare({A1, _, _}, {A2, _, _}) when A1 > A2 -> gt;
compare({_, B1, _}, {_, B2, _}) when B1 < B2 -> lt;
compare({_, B1, _}, {_, B2, _}) when B1 > B2 -> gt;
compare({_, _, C1}, {_, _, C2}) when C1 < C2 -> lt;
compare({_, _, C1}, {_, _, C2}) when C1 > C2 -> gt.

-spec in_range(string() | binary(), string() | binary()) -> boolean().
in_range(Version, Range) when is_binary(Version) ->
    in_range(binary_to_list(Version), Range);
in_range(Version, Range) when is_binary(Range) ->
    in_range(Version, binary_to_list(Range));
in_range(Version, Range) ->
    case parse(Version) of
        {ok, Vsn} ->
            Constraints = parse_range(Range),
            lists:all(fun(C) -> satisfies(Vsn, C) end, Constraints);
        error ->
            false
    end.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

strip_pre(Vsn) ->
    case string:split(Vsn, "-") of
        [Base | _] -> Base;
        _ -> Vsn
    end.

parse_range(Range) ->
    Parts = string:tokens(Range, ","),
    [parse_constraint(string:trim(P)) || P <- Parts].

-spec parse_constraint(string()) -> constraint().
parse_constraint(">=" ++ Rest) ->
    {ok, V} = parse(string:trim(Rest)),
    {'>=', V};
parse_constraint("<=" ++ Rest) ->
    {ok, V} = parse(string:trim(Rest)),
    {'<=', V};
parse_constraint(">" ++ Rest) ->
    case string:trim(Rest) of
        "=" ++ Rest2 ->
            {ok, V} = parse(string:trim(Rest2)),
            {'>=', V};
        Trimmed ->
            {ok, V} = parse(Trimmed),
            {'>', V}
    end;
parse_constraint("<" ++ Rest) ->
    case string:trim(Rest) of
        "=" ++ Rest2 ->
            {ok, V} = parse(string:trim(Rest2)),
            {'<=', V};
        Trimmed ->
            {ok, V} = parse(Trimmed),
            {'<', V}
    end;
parse_constraint("=" ++ Rest) ->
    {ok, V} = parse(string:trim(Rest)),
    {'=', V};
parse_constraint(Other) ->
    {ok, V} = parse(string:trim(Other)),
    {'=', V}.

satisfies(Vsn, {'<', Target}) -> compare(Vsn, Target) =:= lt;
satisfies(Vsn, {'<=', Target}) -> compare(Vsn, Target) =/= gt;
satisfies(Vsn, {'>', Target}) -> compare(Vsn, Target) =:= gt;
satisfies(Vsn, {'>=', Target}) -> compare(Vsn, Target) =/= lt;
satisfies(Vsn, {'=', Target}) -> compare(Vsn, Target) =:= eq.
