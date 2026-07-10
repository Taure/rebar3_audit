-module(rebar3_audit_advisory_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% next_url/1 (cursor-based pagination)
%%
%% GitHub's global advisories endpoint paginates by cursor: the "next"
%% entry in the Link header carries an `after` cursor. It has no `page`
%% parameter, so incrementing a page number refetches the same first page
%% forever. These tests pin the pagination to the Link-header cursor.
%%--------------------------------------------------------------------

next_url_follows_after_cursor_test() ->
    Headers = [
        {"link",
            "<https://api.github.com/advisories?ecosystem=erlang&per_page=100&"
            "after=Y3Vyc29yOnYyOpK0MjAyMi0wNC0xMlQxOTozNjozOVrNOpc%3D>; "
            "rel=\"next\""}
    ],
    ?assertEqual(
        "https://api.github.com/advisories?ecosystem=erlang&per_page=100&"
        "after=Y3Vyc29yOnYyOpK0MjAyMi0wNC0xMlQxOTozNjozOVrNOpc%3D",
        rebar3_audit_advisory:next_url(Headers)
    ).

next_url_is_cursor_not_page_test() ->
    %% Regression guard: the followed URL must carry the `after` cursor and
    %% must never fall back to page-based pagination.
    Headers = [
        {"link",
            "<https://api.github.com/advisories?ecosystem=erlang&per_page=100&"
            "after=abc123>; rel=\"next\""}
    ],
    NextURL = rebar3_audit_advisory:next_url(Headers),
    ?assertNotEqual(nomatch, string:find(NextURL, "after=abc123")),
    %% Must not reintroduce the `&page=` param (distinct from `&per_page=`).
    ?assertEqual(nomatch, string:find(NextURL, "&page=")).

next_url_selects_next_among_prev_and_next_test() ->
    Headers = [
        {"link",
            "<https://api.github.com/advisories?before=PREVCURSOR>; "
            "rel=\"prev\", "
            "<https://api.github.com/advisories?after=NEXTCURSOR>; "
            "rel=\"next\""}
    ],
    ?assertEqual(
        "https://api.github.com/advisories?after=NEXTCURSOR",
        rebar3_audit_advisory:next_url(Headers)
    ).

next_url_last_page_has_no_next_test() ->
    %% Final page: only prev/first links present -> stop paginating.
    Headers = [
        {"link",
            "<https://api.github.com/advisories?before=X>; rel=\"prev\", "
            "<https://api.github.com/advisories?before=Y>; rel=\"first\""}
    ],
    ?assertEqual(undefined, rebar3_audit_advisory:next_url(Headers)).

next_url_no_link_header_test() ->
    ?assertEqual(undefined, rebar3_audit_advisory:next_url([])).
