-module(rebar3_audit_advisory).

-export([fetch/1]).

-define(API_URL, "https://api.github.com/advisories").
-define(PER_PAGE, 100).

-type advisory() :: #{
    ghsa_id := binary(),
    cve_id := binary() | null,
    summary := binary(),
    severity := binary(),
    url := binary(),
    vulnerabilities := [vulnerability()]
}.

-type vulnerability() :: #{
    package := binary(),
    vulnerable_range := binary(),
    patched_version := binary() | null
}.

-export_type([advisory/0, vulnerability/0]).

-spec fetch(Token :: string() | undefined) ->
    {ok, [advisory()]} | {error, term()}.
fetch(Token) ->
    ok = ensure_started(),
    fetch_pages(Token, 1, []).

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

ensure_started() ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    ok.

fetch_pages(Token, Page, Acc) ->
    URL = io_lib:format(
        "~s?ecosystem=erlang&per_page=~b&page=~b",
        [?API_URL, ?PER_PAGE, Page]
    ),
    Headers = headers(Token),
    SSLOpts = ssl_opts(),
    Request = {lists:flatten(URL), Headers},
    HttpOpts = [{ssl, SSLOpts}, {timeout, 30000}],
    Opts = [{body_format, binary}, {full_result, true}],
    case httpc:request(get, Request, HttpOpts, Opts) of
        {ok, {{_, 200, _}, RespHeaders, Body}} ->
            case json:decode(Body) of
                Advisories when is_list(Advisories) ->
                    Parsed = [parse_advisory(A) || A <- Advisories],
                    case length(Advisories) of
                        ?PER_PAGE ->
                            case has_next_page(RespHeaders) of
                                true ->
                                    fetch_pages(Token, Page + 1, Acc ++ Parsed);
                                false ->
                                    {ok, Acc ++ Parsed}
                            end;
                        _ ->
                            {ok, Acc ++ Parsed}
                    end;
                _ ->
                    {error, {unexpected_response, Body}}
            end;
        {ok, {{_, 403, _}, _, _}} ->
            {error, rate_limited};
        {ok, {{_, Status, _}, _, Body}} ->
            {error, {http_error, Status, Body}};
        {error, Reason} ->
            {error, Reason}
    end.

headers(undefined) ->
    [
        {"Accept", "application/vnd.github+json"},
        {"User-Agent", "rebar3_audit"},
        {"X-GitHub-Api-Version", "2022-11-28"}
    ];
headers(Token) ->
    [{"Authorization", "Bearer " ++ Token} | headers(undefined)].

ssl_opts() ->
    CACerts = public_key:cacerts_get(),
    [
        {verify, verify_peer},
        {cacerts, CACerts},
        {customize_hostname_check, [
            {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
        ]}
    ].

has_next_page(Headers) ->
    case proplists:get_value("link", Headers) of
        undefined -> false;
        Link -> string:find(Link, "rel=\"next\"") =/= nomatch
    end.

parse_advisory(
    #{
        <<"ghsa_id">> := GhsaId,
        <<"summary">> := Summary,
        <<"severity">> := Severity,
        <<"html_url">> := Url,
        <<"vulnerabilities">> := Vulns
    } = Advisory
) ->
    CveId = maps:get(<<"cve_id">>, Advisory, null),
    #{
        ghsa_id => GhsaId,
        cve_id => CveId,
        summary => Summary,
        severity => Severity,
        url => Url,
        vulnerabilities => [
            parse_vulnerability(V)
         || V <- Vulns,
            is_erlang_vuln(V)
        ]
    }.

parse_vulnerability(
    #{
        <<"package">> := #{<<"name">> := Name},
        <<"vulnerable_version_range">> := Range
    } = Vuln
) ->
    Patched =
        case maps:get(<<"first_patched_version">>, Vuln, null) of
            null -> null;
            #{<<"identifier">> := V} -> V;
            _ -> null
        end,
    #{
        package => Name,
        vulnerable_range => Range,
        patched_version => Patched
    }.

is_erlang_vuln(#{<<"package">> := #{<<"ecosystem">> := <<"erlang">>}}) -> true;
is_erlang_vuln(_) -> false.
