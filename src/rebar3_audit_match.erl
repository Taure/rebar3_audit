-module(rebar3_audit_match).

-export([check/3]).

-spec check(
    Deps :: [{LocalName :: string(), PkgName :: string(), Version :: string()}],
    Advisories :: [rebar3_audit_advisory:advisory()],
    IgnoreIds :: [string()]
) -> [map()].
check(Deps, Advisories, IgnoreIds) ->
    IgnoreSet = sets:from_list([list_to_binary(Id) || Id <- IgnoreIds]),
    lists:foldl(
        fun({_LocalName, PkgName, Version}, Acc) ->
            check_dep(PkgName, Version, Advisories, IgnoreSet) ++ Acc
        end,
        [],
        Deps
    ).

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

check_dep(PkgName, Version, Advisories, IgnoreSet) ->
    PkgBin = list_to_binary(PkgName),
    lists:filtermap(
        fun(Advisory) ->
            check_advisory(PkgBin, Version, Advisory, IgnoreSet)
        end,
        Advisories
    ).

check_advisory(
    PkgBin,
    Version,
    #{
        ghsa_id := GhsaId,
        cve_id := CveId,
        summary := Summary,
        severity := Severity,
        url := Url,
        vulnerabilities := Vulns
    },
    IgnoreSet
) ->
    case sets:is_element(GhsaId, IgnoreSet) of
        true ->
            false;
        false ->
            case find_matching_vuln(PkgBin, Version, Vulns) of
                {ok, #{vulnerable_range := Range, patched_version := Patched}} ->
                    {true, #{
                        ghsa_id => GhsaId,
                        cve_id => CveId,
                        package => PkgBin,
                        current_version => list_to_binary(Version),
                        severity => Severity,
                        vulnerable_range => Range,
                        patched_version => Patched,
                        summary => Summary,
                        url => Url
                    }};
                none ->
                    false
            end
    end.

find_matching_vuln(_PkgBin, _Version, []) ->
    none;
find_matching_vuln(PkgBin, Version, [
    #{package := PkgBin, vulnerable_range := Range} = Vuln | _
]) when
    Range =/= null
->
    case rebar3_audit_version:in_range(Version, Range) of
        true -> {ok, Vuln};
        false -> none
    end;
find_matching_vuln(PkgBin, Version, [_ | Rest]) ->
    find_matching_vuln(PkgBin, Version, Rest).
