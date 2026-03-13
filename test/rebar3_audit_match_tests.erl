-module(rebar3_audit_match_tests).

-include_lib("eunit/include/eunit.hrl").

advisory(PkgName, Range) ->
    advisory(PkgName, Range, null).

advisory(PkgName, Range, Patched) ->
    #{
        ghsa_id => <<"GHSA-test-1234">>,
        cve_id => <<"CVE-2025-0001">>,
        summary => <<"Test vulnerability">>,
        severity => <<"high">>,
        url => <<"https://github.com/advisories/GHSA-test-1234">>,
        vulnerabilities => [
            #{
                package => list_to_binary(PkgName),
                vulnerable_range => list_to_binary(Range),
                patched_version =>
                    case Patched of
                        null -> null;
                        _ -> list_to_binary(Patched)
                    end
            }
        ]
    }.

%%--------------------------------------------------------------------
%% check
%%--------------------------------------------------------------------

no_match_test() ->
    Deps = [{"cowboy", "cowboy", "2.12.0"}],
    Advisories = [advisory("cowboy", ">= 1.0.0, < 2.0.0")],
    ?assertEqual([], rebar3_audit_match:check(Deps, Advisories, [])).

match_test() ->
    Deps = [{"cowboy", "cowboy", "1.5.0"}],
    Advisories = [advisory("cowboy", ">= 1.0.0, < 2.0.0", "2.0.0")],
    Result = rebar3_audit_match:check(Deps, Advisories, []),
    ?assertEqual(1, length(Result)),
    [#{package := Pkg, severity := Sev}] = Result,
    ?assertEqual(<<"cowboy">>, Pkg),
    ?assertEqual(<<"high">>, Sev).

no_match_different_pkg_test() ->
    Deps = [{"ranch", "ranch", "1.5.0"}],
    Advisories = [advisory("cowboy", ">= 1.0.0, < 2.0.0")],
    ?assertEqual([], rebar3_audit_match:check(Deps, Advisories, [])).

ignore_advisory_test() ->
    Deps = [{"cowboy", "cowboy", "1.5.0"}],
    Advisories = [advisory("cowboy", ">= 1.0.0, < 2.0.0")],
    ?assertEqual(
        [], rebar3_audit_match:check(Deps, Advisories, ["GHSA-test-1234"])
    ).

multiple_deps_test() ->
    Deps = [
        {"cowboy", "cowboy", "1.5.0"},
        {"ranch", "ranch", "2.0.0"}
    ],
    Advisories = [
        advisory("cowboy", ">= 1.0.0, < 2.0.0"),
        advisory("ranch", "< 1.8.0")
    ],
    Result = rebar3_audit_match:check(Deps, Advisories, []),
    ?assertEqual(1, length(Result)),
    [#{package := <<"cowboy">>}] = Result.

empty_deps_test() ->
    ?assertEqual(
        [], rebar3_audit_match:check([], [advisory("x", "< 1.0.0")], [])
    ).

empty_advisories_test() ->
    ?assertEqual([], rebar3_audit_match:check([{"x", "x", "1.0.0"}], [], [])).
