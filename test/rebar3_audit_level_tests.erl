-module(rebar3_audit_level_tests).

-include_lib("eunit/include/eunit.hrl").

%% Test the severity filtering logic used in do/1.
%% We replicate the filter inline since parse_level/severity_rank are internal.

-define(FILTER(Vulns, Level), [
    V
 || #{severity := S} = V <- Vulns, rank(S) >= Level
]).

rank(<<"critical">>) -> 4;
rank(<<"high">>) -> 3;
rank(<<"medium">>) -> 2;
rank(<<"low">>) -> 1;
rank(_) -> 0.

level(critical) -> 4;
level(high) -> 3;
level(medium) -> 2;
level(low) -> 1.

vuln(Severity) ->
    #{severity => Severity, ghsa_id => <<"test">>}.

%%--------------------------------------------------------------------
%% Tests
%%--------------------------------------------------------------------

level_low_fails_on_all_test() ->
    Vulns = [
        vuln(<<"low">>),
        vuln(<<"medium">>),
        vuln(<<"high">>),
        vuln(<<"critical">>)
    ],
    ?assertEqual(4, length(?FILTER(Vulns, level(low)))).

level_high_skips_medium_and_low_test() ->
    Vulns = [
        vuln(<<"low">>),
        vuln(<<"medium">>),
        vuln(<<"high">>),
        vuln(<<"critical">>)
    ],
    Failing = ?FILTER(Vulns, level(high)),
    ?assertEqual(2, length(Failing)),
    ?assert(
        lists:all(
            fun(#{severity := S}) ->
                S =:= <<"high">> orelse S =:= <<"critical">>
            end,
            Failing
        )
    ).

level_critical_only_test() ->
    Vulns = [
        vuln(<<"low">>),
        vuln(<<"medium">>),
        vuln(<<"high">>),
        vuln(<<"critical">>)
    ],
    Failing = ?FILTER(Vulns, level(critical)),
    ?assertEqual([vuln(<<"critical">>)], Failing).

level_medium_skips_low_test() ->
    Vulns = [vuln(<<"low">>), vuln(<<"medium">>)],
    Failing = ?FILTER(Vulns, level(medium)),
    ?assertEqual([vuln(<<"medium">>)], Failing).

unknown_severity_never_fails_test() ->
    Vulns = [vuln(<<"unknown">>)],
    ?assertEqual([], ?FILTER(Vulns, level(low))).

no_vulns_test() ->
    ?assertEqual([], ?FILTER([], level(low))).

all_below_level_passes_test() ->
    Vulns = [vuln(<<"low">>), vuln(<<"medium">>)],
    ?assertEqual([], ?FILTER(Vulns, level(high))).
