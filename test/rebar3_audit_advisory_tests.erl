-module(rebar3_audit_advisory_tests).

-include_lib("eunit/include/eunit.hrl").

%% Regression: the advisories endpoint is cursor-paginated, so pagination must
%% follow the Link header's rel="next" URL. A `page=N` scheme loops on page one
%% forever once an ecosystem exceeds a single page.

next_url_follows_rel_next_test() ->
    Link =
        "<https://api.github.com/advisories?ecosystem=erlang&per_page=100&"
        "after=CURSOR123>; rel=\"next\", "
        "<https://api.github.com/advisories?ecosystem=erlang&per_page=100&"
        "after=LAST>; rel=\"last\"",
    ?assertEqual(
        {ok,
            "https://api.github.com/advisories?ecosystem=erlang&per_page=100&"
            "after=CURSOR123"},
        rebar3_audit_advisory:next_url([{"link", Link}])
    ).

next_url_none_on_last_page_test() ->
    Link =
        "<https://api.github.com/advisories?ecosystem=erlang&per_page=100&"
        "after=FIRST>; rel=\"prev\"",
    ?assertEqual(none, rebar3_audit_advisory:next_url([{"link", Link}])).

next_url_none_without_link_header_test() ->
    ?assertEqual(none, rebar3_audit_advisory:next_url([])).
