-module(rebar3_audit_version_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% parse
%%--------------------------------------------------------------------

parse_semver_test() ->
    ?assertEqual({ok, {1, 2, 3}}, rebar3_audit_version:parse("1.2.3")).

parse_two_part_test() ->
    ?assertEqual({ok, {1, 2, 0}}, rebar3_audit_version:parse("1.2")).

parse_binary_test() ->
    ?assertEqual({ok, {2, 0, 0}}, rebar3_audit_version:parse(<<"2.0.0">>)).

parse_with_pre_release_test() ->
    ?assertEqual({ok, {1, 0, 0}}, rebar3_audit_version:parse("1.0.0-rc.1")).

parse_invalid_test() ->
    ?assertEqual(error, rebar3_audit_version:parse("not_a_version")).

%%--------------------------------------------------------------------
%% compare
%%--------------------------------------------------------------------

compare_equal_test() ->
    ?assertEqual(eq, rebar3_audit_version:compare({1, 2, 3}, {1, 2, 3})).

compare_lt_major_test() ->
    ?assertEqual(lt, rebar3_audit_version:compare({1, 0, 0}, {2, 0, 0})).

compare_gt_minor_test() ->
    ?assertEqual(gt, rebar3_audit_version:compare({1, 3, 0}, {1, 2, 0})).

compare_lt_patch_test() ->
    ?assertEqual(lt, rebar3_audit_version:compare({1, 2, 3}, {1, 2, 4})).

%%--------------------------------------------------------------------
%% parse_constraint
%%--------------------------------------------------------------------

parse_constraint_gte_test() ->
    ?assertEqual(
        {'>=', {1, 0, 0}}, rebar3_audit_version:parse_constraint(">= 1.0.0")
    ).

parse_constraint_lt_test() ->
    ?assertEqual(
        {'<', {2, 0, 0}}, rebar3_audit_version:parse_constraint("< 2.0.0")
    ).

parse_constraint_eq_test() ->
    ?assertEqual(
        {'=', {1, 5, 0}}, rebar3_audit_version:parse_constraint("= 1.5.0")
    ).

%%--------------------------------------------------------------------
%% in_range
%%--------------------------------------------------------------------

in_range_simple_lt_test() ->
    ?assert(rebar3_audit_version:in_range("1.0.0", "< 2.0.0")).

in_range_simple_lt_false_test() ->
    ?assertNot(rebar3_audit_version:in_range("2.0.0", "< 2.0.0")).

in_range_compound_test() ->
    ?assert(rebar3_audit_version:in_range("1.5.0", ">= 1.0.0, < 2.0.0")).

in_range_compound_below_test() ->
    ?assertNot(rebar3_audit_version:in_range("0.9.0", ">= 1.0.0, < 2.0.0")).

in_range_compound_above_test() ->
    ?assertNot(rebar3_audit_version:in_range("2.0.0", ">= 1.0.0, < 2.0.0")).

in_range_exact_match_test() ->
    ?assert(rebar3_audit_version:in_range("1.2.3", "= 1.2.3")).

in_range_exact_no_match_test() ->
    ?assertNot(rebar3_audit_version:in_range("1.2.4", "= 1.2.3")).

in_range_binary_inputs_test() ->
    ?assert(
        rebar3_audit_version:in_range(<<"1.5.0">>, <<">= 1.0.0, < 2.0.0">>)
    ).

in_range_invalid_version_test() ->
    ?assertNot(rebar3_audit_version:in_range("invalid", ">= 1.0.0")).
