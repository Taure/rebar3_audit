-module(rebar3_audit_prv).

-behaviour(provider).

-export([init/1, do/1, format_error/1]).

-define(PROVIDER, audit).
-define(DEPS, [lock]).

init(State) ->
    Provider = providers:create([
        {name, ?PROVIDER},
        {module, ?MODULE},
        {bare, true},
        {deps, ?DEPS},
        {example, "rebar3 audit"},
        {opts, [
            {ignore, $i, "ignore", string,
                "GHSA ID to ignore (repeat for multiple)"},
            {token, $t, "token", string,
                "GitHub token for API access (or set GITHUB_TOKEN)"},
            {format, $f, "format", {string, "human"},
                "Output format: human, json"},
            {level, $l, "level", {string, "low"},
                "Minimum severity to fail on: critical, high, medium, low"}
        ]},
        {short_desc, "Audit dependencies for known vulnerabilities"},
        {desc,
            "Scans project dependencies against the GitHub Advisory Database\n"
            "for known security vulnerabilities in the Erlang/Hex ecosystem."}
    ]),
    {ok, rebar_state:add_provider(State, Provider)}.

do(State) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    Token = resolve_token(Args),
    IgnoreIds = collect_ignores(Args),
    Format = proplists:get_value(format, Args, "human"),
    Level = parse_level(proplists:get_value(level, Args, "low")),
    Deps = parse_lock(State),
    case Deps of
        [] ->
            rebar_api:info("No dependencies found in lock file.", []),
            {ok, State};
        _ ->
            rebar_api:info(
                "Fetching advisories from GitHub Advisory Database...", []
            ),
            case rebar3_audit_advisory:fetch(Token) of
                {ok, Advisories} ->
                    Vulns = rebar3_audit_match:check(
                        Deps, Advisories, IgnoreIds
                    ),
                    report(Vulns, Deps, Format),
                    Failing = [
                        V
                     || #{severity := S} = V <- Vulns,
                        severity_rank(S) >= Level
                    ],
                    case Failing of
                        [] ->
                            {ok, State};
                        _ ->
                            {error,
                                {?MODULE,
                                    {vulnerabilities_found, length(Failing)}}}
                    end;
                {error, Reason} ->
                    {error, {?MODULE, {fetch_failed, Reason}}}
            end
    end.

format_error({vulnerabilities_found, Count}) ->
    io_lib:format("Found ~b known ~s", [
        Count,
        case Count of
            1 -> "vulnerability";
            _ -> "vulnerabilities"
        end
    ]);
format_error({fetch_failed, Reason}) ->
    io_lib:format("Failed to fetch advisories: ~p", [Reason]);
format_error(Reason) ->
    io_lib:format("~p", [Reason]).

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

resolve_token(Args) ->
    case proplists:get_value(token, Args) of
        undefined ->
            case os:getenv("GITHUB_TOKEN") of
                false -> undefined;
                Token -> Token
            end;
        Token ->
            Token
    end.

collect_ignores(Args) ->
    [Id || {ignore, Id} <- Args].

parse_lock(State) ->
    LockFile = filename:join(rebar_dir:root_dir(State), "rebar.lock"),
    case file:consult(LockFile) of
        {ok, [[]]} ->
            [];
        {ok, [{_Vsn, Packages}, _Hashes]} ->
            [
                {binary_to_list(LocalName), pkg_name(Spec), pkg_version(Spec)}
             || {LocalName, Spec, _Level} <- Packages,
                is_hex(Spec)
            ];
        {ok, [{_Vsn, Packages}]} ->
            [
                {binary_to_list(LocalName), pkg_name(Spec), pkg_version(Spec)}
             || {LocalName, Spec, _Level} <- Packages,
                is_hex(Spec)
            ];
        {error, enoent} ->
            rebar_api:warn(
                "No rebar.lock file found. Run rebar3 lock first.", []
            ),
            [];
        {error, Reason} ->
            rebar_api:abort("Failed to read rebar.lock: ~p", [Reason]),
            []
    end.

is_hex({pkg, _, _}) -> true;
is_hex({pkg, _, _, _}) -> true;
is_hex(_) -> false.

pkg_name({pkg, Name, _}) -> binary_to_list(Name);
pkg_name({pkg, Name, _, _}) -> binary_to_list(Name).

pkg_version({pkg, _, Vsn}) -> binary_to_list(Vsn);
pkg_version({pkg, _, Vsn, _}) -> binary_to_list(Vsn).

vuln_to_map(#{
    ghsa_id := GhsaId,
    cve_id := CveId,
    package := Package,
    current_version := CurrentVsn,
    severity := Severity,
    vulnerable_range := Range,
    patched_version := Patched,
    summary := Summary,
    url := Url
}) ->
    #{
        <<"ghsa_id">> => GhsaId,
        <<"cve_id">> => CveId,
        <<"package">> => Package,
        <<"current_version">> => CurrentVsn,
        <<"severity">> => Severity,
        <<"vulnerable_range">> => Range,
        <<"patched_version">> => Patched,
        <<"summary">> => Summary,
        <<"url">> => Url
    }.

report([], Deps, _Format) ->
    rebar_api:info("No vulnerabilities found in ~b dependencies. ✓", [
        length(Deps)
    ]);
report(Vulns, Deps, "json") ->
    JSON = json:encode(#{
        <<"vulnerabilities">> => [vuln_to_map(V) || V <- Vulns],
        <<"dependencies_scanned">> => length(Deps)
    }),
    io:put_chars(JSON),
    io:nl();
report(Vulns, Deps, _Human) ->
    rebar_api:warn(
        "~n╔══════════════════════════════════════════════════════════╗", []
    ),
    rebar_api:warn("║  ~b ~s found in ~b dependencies  ║", [
        length(Vulns),
        case length(Vulns) of
            1 -> "vulnerability ";
            _ -> "vulnerabilities"
        end,
        length(Deps)
    ]),
    rebar_api:warn(
        "╚══════════════════════════════════════════════════════════╝~n", []
    ),
    lists:foreach(fun report_vuln/1, Vulns).

report_vuln(#{
    ghsa_id := GhsaId,
    cve_id := CveId,
    package := Package,
    severity := Severity,
    vulnerable_range := Range,
    patched_version := Patched,
    summary := Summary,
    url := Url,
    current_version := CurrentVsn
}) ->
    SevStr = severity_label(Severity),
    rebar_api:warn("  ~s ~s (~s)", [SevStr, Package, CurrentVsn]),
    rebar_api:warn("  │ ~s", [Summary]),
    rebar_api:warn("  │ Advisory:   ~s~s", [
        GhsaId,
        case CveId of
            null -> "";
            _ -> io_lib:format(" (~s)", [CveId])
        end
    ]),
    rebar_api:warn("  │ Vulnerable: ~s", [Range]),
    case Patched of
        null -> rebar_api:warn("  │ Fix:        No fix available", []);
        _ -> rebar_api:warn("  │ Fix:        Upgrade to ~s", [Patched])
    end,
    rebar_api:warn("  │ URL:        ~s", [Url]),
    rebar_api:warn("  │", []).

parse_level("critical") ->
    4;
parse_level("high") ->
    3;
parse_level("medium") ->
    2;
parse_level("low") ->
    1;
parse_level(Other) ->
    rebar_api:warn("Unknown severity level ~p, defaulting to low", [Other]),
    1.

severity_rank(<<"critical">>) -> 4;
severity_rank(<<"high">>) -> 3;
severity_rank(<<"medium">>) -> 2;
severity_rank(<<"low">>) -> 1;
severity_rank(_) -> 0.

severity_label(<<"critical">>) -> "🔴 CRITICAL";
severity_label(<<"high">>) -> "🟠 HIGH    ";
severity_label(<<"medium">>) -> "🟡 MEDIUM  ";
severity_label(<<"low">>) -> "🟢 LOW     ";
severity_label(_) -> "⚪ UNKNOWN ".
