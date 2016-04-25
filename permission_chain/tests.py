from __future__ import unicode_literals

import itertools

import re

from django.contrib.auth.models import User
from django.db.models import Q
from django.test import TestCase


from mock import MagicMock
from permission_chain.permissions import ChainPermission, OBJECT_ACTIONS, \
    RecursiveChainProcessor, ALL_ACTION_NAMES, QueryFragment, \
    InvalidChainException, ChainProcessor
from permission_chain.signals import get_additional_chains, \
    get_additional_chain_fragments, process_additional_chain
from permission_chain.views import ChainViewMixin

ALL_PERMS = {
    "add": ["create"],
    "change": ["update", "partial_update"],
    "view": ["list", "retrieve"],
    "delete": ["destroy"]
}

def list_powerset(lst):
    # the power set of the empty set has one element, the empty set
    result = [[]]
    for x in lst:
        # for every additional element in our set
        # the power set consists of the subsets that don't
        # contain this element (just take the previous power set)
        # plus the subsets that do contain the element (use list
        # comprehension to add [x] onto everything in the
        # previous power set)
        result.extend([subset + [x] for subset in result])
    return result


ALL_ACTION_COMBINATIONS = list_powerset(ALL_ACTION_NAMES)
ALL_PERM_COMBINATIONS = list_powerset(ALL_PERMS.keys())


def MockClass(p):
    class X(object):
        def __new__(cls, *args, **kwargs):
            return p
    return X


class ChainPermissionTestCase(TestCase):
    def setUp(self):
        self.request = MagicMock()
        self.request.user = User.objects.create_user("test user")
        self.view = MagicMock()
        self.chain_processor = MagicMock()
        self.chain_processor.process.return_value = False
        self.chain_processor_class = MockClass(self.chain_processor)

    def check_perm(self, p, request, view, expected, msg=None):
        if view.action not in OBJECT_ACTIONS:
            self.assertEqual(
                p.has_permission(request, view),
                expected,
                msg
            )
        else:
            obj = {}
            self.assertEqual(
                p.has_object_permission(request, view, obj),
                expected,
                msg
            )

    def test_chain_filter_actions(self):
        cl = ChainPermission(chain_processor_class=self.chain_processor_class)
        self.view.action = "list"
        p = cl()
        self.assertEqual(
            p.has_permission(self.request, self.view),
            True,
            "List should be allowed"
        )

    def test_unconstrained(self):
        for allowed in ALL_ACTION_COMBINATIONS:
            cl = ChainPermission(
                unconstrained_actions=allowed,
                chain_processor_class=self.chain_processor_class,
                chain_filter_actions=[])
            p = cl()
            for a in ALL_ACTION_NAMES:
                self.view.action = a
                self.check_perm(p, self.request, self.view, a in allowed,
                                "Action: %s, allowed actions: %s" % (
                                    a, allowed
                                ))

    def test_staff(self):
        self.request2 = MagicMock()
        self.request2.user = User.objects.create_user("test user 2")
        self.request2.user.is_staff = True
        self.request2.user.save()

        for allowed in ALL_ACTION_COMBINATIONS:
            cl = ChainPermission(
                staff_actions=allowed,
                chain_processor_class=self.chain_processor_class,
                chain_filter_actions=[])
            p = cl()
            for a in ALL_ACTION_NAMES:
                self.view.action = a
                self.check_perm(p, self.request2, self.view, a in allowed,
                                "Action: %s, allowed actions: %s" % (
                                    a, allowed
                                ))
                self.check_perm(p, self.request, self.view, False)

    def test_django(self):
        self.request.user = MagicMock()
        self.request.user.is_staff = False
        app_label = "app"
        model_name = "model"
        pattern = re.compile(app_label + "\." + "([^_]+)_" + model_name)

        for perms in ALL_PERM_COMBINATIONS:
            def has_perm(s):
                perm = pattern.match(s).group(1)
                return perm in perms
            self.request.user.has_perm = has_perm
            for p, actions in ALL_PERMS.items():
                cl = ChainPermission(
                    chain_processor_class=self.chain_processor_class,
                    django_permission_pattern=app_label + ".%s_" + model_name,
                    django_actions=actions,
                    chain_filter_actions=[]
                )
                permission = cl()

                for a in actions:
                    self.view.action = a
                    self.check_perm(
                        permission, self.request, self.view, p in perms,
                        "Perm: %s, action %s, allowed perms: %s" % (
                            p, a, perms
                        )
                    )

    def test_django_extra_perm(self):
        self.request.user = MagicMock()
        self.request.user.is_staff = False
        app_label = "app"
        model_name = "model"
        pattern = re.compile(app_label + "\." + "([^_]+)_" + model_name)
        perms = {"list": "view", "foo": "bar"}

        def has_perm(s):
            perm = pattern.match(s).group(1)
            return perm in perms.values()

        self.request.user.has_perm = has_perm

        cl = ChainPermission(
            chain_processor_class=self.chain_processor_class,
            django_permission_pattern=app_label + ".%s_" + model_name,
            django_actions=perms,
            chain_filter_actions=False
        )

        permission = cl()

        for a in (ALL_ACTION_NAMES + ["foo"]):
            self.view.action = a
            self.check_perm(
                permission,
                self.request,
                self.view,
                a in perms.keys(),
                "Perm: %s, action %s, allowed perms: %s" %
                (perms.get(a, "None"), a, perms)
            )


class DummyFilterQueryset(object):
    def filter_queryset(self, queryset):
        return queryset


class NonLeakyMixin(ChainViewMixin, DummyFilterQueryset):
    chain_permission = MagicMock()
    request = MagicMock()


class LeakyMixin(ChainViewMixin, DummyFilterQueryset):
    chain_permission = MagicMock()
    request = MagicMock()


class ChainManagerTestCase(TestCase):

    def test_non_leaky_retrieval(self):
        cm = NonLeakyMixin()
        cm.action = "retrieve"
        cm.filter_queryset_by_chains = MagicMock()
        q = MagicMock()
        cm.chain_permission.skip_chain_filter.return_value = False
        cm.filter_queryset(q)
        cm.filter_queryset_by_chains.assert_called_once_with(
            q, NonLeakyMixin.request, cm)

    def test_leaky_retrieval(self):
        cm = LeakyMixin()
        cm.action = "retrieve"
        cm.filter_queryset_by_chains = MagicMock()
        q = MagicMock()
        cm.chain_permission.skip_chain_filter.return_value = True
        cm.filter_queryset(q)
        cm.filter_queryset_by_chains.assert_not_called()

    def test_list(self):
        cm = LeakyMixin()
        cm.action = "list"
        cm.filter_queryset_by_chains = MagicMock()
        q = MagicMock()
        cm.chain_permission.skip_chain_filter.return_value = False
        cm.filter_queryset(q)
        cm.filter_queryset_by_chains.assert_called_once_with(
            q, LeakyMixin.request, cm)

    def test_list_skip_chain_filter(self):
        cm = LeakyMixin()
        cm.action = "list"
        cm.filter_queryset_by_chains = MagicMock()
        q = MagicMock()
        cm.chain_permission.skip_chain_filter.return_value = True
        cm.filter_queryset(q)
        cm.filter_queryset_by_chains.assert_not_called()


class ThreeRecursiveChainProcessor(ChainProcessor):

    map = {
        "OBJ_SIMPLE_3": [("USER_SIMPLE",)],
        "OBJ_MULTIPLE_3AA": [("USER_MULTIPLE",)],
        "OBJ_MULTIPLE_3AB": [("USER_MULTIPLE",)],
        "OBJ_MULTIPLE_3BA": [("USER_MULTIPLE",)],
        "OBJ_MULTIPLE_3BB": [("USER_MULTIPLE",)]
    }

    def get_chains(self, request=None, view=None, obj=None):
        chains = super(ThreeRecursiveChainProcessor, self).get_chains(
            request=request, view=view, obj=obj)
        return itertools.chain(chains, self.map.get(obj, []))

    def get_chain_fragment(self, request, view):
        fragment = super(ThreeRecursiveChainProcessor, self).get_chain_fragment(
            request, view)
        if fragment:
            return fragment | QueryFragment("user")
        else:
            return QueryFragment("user")


class TwoRecursiveChainProcessor(RecursiveChainProcessor):

    next_chain_processor_class = ThreeRecursiveChainProcessor

    map = {
        "OBJ_SIMPLE_2": ["OBJ_SIMPLE_3"],
        "OBJ_MULTIPLE_2A": ["OBJ_MULTIPLE_3AA", "OBJ_MULTIPLE_3AB"],
        "OBJ_MULTIPLE_2B": ["OBJ_MULTIPLE_3BA","OBJ_MULTIPLE_3BB"],
        "OBJ_EMPTY_2": ["OBJ_EMPTY_3"]
    }

    def get_next_links(self, request=None, view=None, obj=None):
        if obj is not None:
            return self.map.get(obj, [])
        else:
            return []

    def next_link_chain_prefixes(self, request=None, view=None):
        return ["three_a", "three_b"]


class OneRecursiveChainProcessor(RecursiveChainProcessor):

    next_chain_processor_class = TwoRecursiveChainProcessor

    map = {
        "OBJ_SIMPLE_1": ["OBJ_SIMPLE_2"],
        "OBJ_MULTIPLE_1": ["OBJ_MULTIPLE_2A", "OBJ_MULTIPLE_2B"],
        "OBJ_EMPTY_1": ["OBJ_EMPTY_2"]
    }

    def get_chains(self, request=None, view=None, obj=None):
        return super(OneRecursiveChainProcessor, self).get_chains(request,
                                                                  view,
                                                                  obj)

    def get_next_links(self, request=None, view=None, obj=None):
        if obj is not None:
            return self.map.get(obj, [])
        else:
            return []

    def next_link_chain_prefixes(self, request=None, view=None):
        return ["two"]


class EmptyFilterArgsChainProcessor(RecursiveChainProcessor):
    next_chain_processor_class =  OneRecursiveChainProcessor
    def get_next_links(self, request=None, view=None, obj=None):
        return []
    def next_link_chain_prefixes(self, request=None, view=None):
        return []


class ZeroRecursiveChainProcessor(RecursiveChainProcessor):
    next_chain_processor_class = EmptyFilterArgsChainProcessor

    def get_chain_fragment(self, request=None, view=None):
        return super(ZeroRecursiveChainProcessor, self).get_chain_fragment(
            request, view
        )

    def get_next_links(self, request=None, view=None, obj=None):
        return [(("EMPTY", "NONE"),)]

    def next_link_chain_prefixes(self, request=None, view=None):
        return ["empty"]


class RecursiveChainManagerTestCase(TestCase):

    def setUp(self):
        self.request = MagicMock()
        self.view = MagicMock()
        self.one_manager = OneRecursiveChainProcessor()

    def test_simple_chain(self):
        chains = self.one_manager.get_chains(obj="OBJ_SIMPLE_1")
        self.assertEqual(list(chains), [("USER_SIMPLE",
                                         "OBJ_SIMPLE_3",
                                         "OBJ_SIMPLE_2")])

    def test_multiple_chains(self):
        chains = self.one_manager.get_chains(obj="OBJ_MULTIPLE_1")
        chains = list(chains)
        self.assertEqual(len(chains), 4)
        for one in ("A", "B"):
            for two in ("A", "B"):
                self.assertIn(("USER_MULTIPLE",
                               "OBJ_MULTIPLE_3%s%s" % (one, two),
                               "OBJ_MULTIPLE_2%s"%one),
                              chains)

    def test_empty_recursive_chains(self):
        chains = self.one_manager.get_chains(obj="OBJ_EMPTY_1")
        self.assertEqual(len(list(chains)), 0)

    def test_empty_next_link(self):
        chains = self.one_manager.get_chains(obj="OBJ_EMPTY_2")
        self.assertEqual(len(list(chains)), 0)

    def test_build_simple_filter_args(self):
        request = MagicMock()
        user = User.objects.create_user(username="test")
        queries = self.one_manager.get_chain_fragment(request, self.view)\
            .to_query_filter(user)
        self.assertTrue(
            repr(queries) == repr(Q(**{"two__three_a__user":user}) |
                                  Q(**{"two__three_b__user":user})) or
            repr(queries) == repr(Q(**{"two__three_b__user": user}) |
                                  Q(**{"two__three_a__user": user}))
        )

    def test_empty_recursive_filter_args(self):
        self.assertRaises(
            InvalidChainException,
            ZeroRecursiveChainProcessor().get_chain_fragment,
            self.request, self.view
        )

    def test_empty_next_filter_args(self):
        self.assertRaises(
            InvalidChainException,
            ZeroRecursiveChainProcessor().get_chain_fragment,
            self.request, self.view
        )


class QueryFragmentTestCase(TestCase):

    def test_compare_constant_fragments(self):
        q1 = QueryFragment("hello")
        q2 = QueryFragment("hello")
        q3 = QueryFragment("hello2")
        self.assertEqual(q1, q2)
        self.assertNotEqual(q1, q3)

    def test_and_fragments(self):
        q1 = QueryFragment("hello")
        q2 = QueryFragment("hello")
        q3 = q1 & q2
        self.assertEqual(q3.values, {q1, q2})
        self.assertEqual(q3.query_type, QueryFragment.AND)

    def test_or_fragments(self):
        q1 = QueryFragment("hello")
        q2 = QueryFragment("hello")
        q3 = q1 | q2
        self.assertEqual(q3.values, {q1, q2})
        self.assertEqual(q3.query_type, QueryFragment.OR)

    def generate_and_or_and_fragment(self):
        q1 = QueryFragment("hello") & QueryFragment("hello")
        q2 = QueryFragment("hello") & QueryFragment("hello")
        q3 = QueryFragment("hello") & QueryFragment("hello")
        q4 = QueryFragment("hello") & QueryFragment("hello")
        qa = q1 | q2
        qb = q3 | q4
        return qa & qb

    def check_fragment(self, q, value):
        self.assertEqual(q.query_type, QueryFragment.AND)
        self.assertEqual(len(q.values), 2)
        for v in q.values:
            self.assertEqual(v.query_type, QueryFragment.OR)
            self.assertEqual(len(v.values), 2)
            for w in v.values:
                self.assertEqual(w.query_type, QueryFragment.AND)
                self.assertEqual(len(v.values), 2)
                for x in w.values:
                    self.assertEqual(x, QueryFragment(value))

    def test_and_or_fragments(self):
        q = self.generate_and_or_and_fragment()
        self.check_fragment(q, "hello")

    def test_add_prefix(self):
        q = self.generate_and_or_and_fragment()
        qprime = q.add_prefix("prefix")
        self.check_fragment(qprime, "prefix__hello")

    def test_add_prefix_kwargs(self):
        q = QueryFragment("fixed", fixed_arg=False)
        qprime = q.add_prefix("prefix")
        self.assertEqual(qprime.query_type, QueryFragment.CONST)
        self.assertEqual(qprime.value, "prefix__fixed")
        self.assertEqual(qprime.kwargs["fixed_arg"], False)

    def to_query_filter(self):
        q1 = QueryFragment("hello1")
        q2 = QueryFragment("hello2")
        query_filter = (q1 | q2).to_query_filter("arg")
        qf = Q(**{"hello1": "arg"}) | Q(**{"hello2": "arg"})
        self.assertEqual(repr(query_filter), repr(qf))

        query_filter = (q1 & q2).to_query_filter("arg")
        qf = Q(**{"hello1": "arg"}) & Q(**{"hello2": "arg"})
        self.assertEqual(repr(query_filter), repr(qf))


def add_chain(sender, **kwargs):
    chain_generator = kwargs.pop("chain_generator")
    def f(processor, request, view, obj):
        return "NEW CHAIN"
    chain_generator.append(f)


def add_fragment(sender, **kwargs):
    fragments = kwargs.pop("fragments")
    request = kwargs.pop("request")
    view = kwargs.pop("view")
    fragments.append(QueryFragment("query"))


def process_chain(sender, **kwargs):
    result = kwargs.pop("result")
    request = kwargs.pop("request")
    view = kwargs.pop("view")
    obj = kwargs.pop("obj")
    validated_data = kwargs.pop("validated_data")
    if obj == "OBJ_SIMPLE_3":
        result["result"] = True


class SignalTestCase(TestCase):

    def setUp(self):
        get_additional_chains.connect(add_chain,
                                      sender=OneRecursiveChainProcessor,
                                      dispatch_uid="add_chain")
        get_additional_chain_fragments.connect(
            add_fragment,
            sender=ZeroRecursiveChainProcessor,
            dispatch_uid="add_fragment")
        process_additional_chain.connect(process_chain,
                                         sender=ThreeRecursiveChainProcessor,
                                         dispatch_uid="process_chain")
        self.request = MagicMock()
        self.request.user = User.objects.create_user("test user")
        self.view = MagicMock()
        self.view.get_chains.return_value = []
        self.view.action = "get"

    def tearDown(self):
        get_additional_chains.disconnect(add_chain, dispatch_uid="add_chain")
        get_additional_chain_fragments.disconnect(add_fragment,
                                                  dispatch_uid="add_fragment")
        process_additional_chain.disconnect(process_chain,
                                            dispatch_uid="process_chain")

    def test_add_chain(self):
        chains = OneRecursiveChainProcessor().get_chains(obj="OBJ_SIMPLE_1")
        self.assertIn("NEW CHAIN", chains)

        chains = TwoRecursiveChainProcessor().get_chains(None, None,
                                                         obj="OBJ_SIMPLE_1")
        self.assertNotIn("NEW CHAIN", chains)

    def test_add_fragment(self):
        q = ZeroRecursiveChainProcessor().get_chain_fragment(self.request,
                                                             self.view)
        self.assertEqual(q.value, "query")
        self.assertRaises(
            InvalidChainException,
            EmptyFilterArgsChainProcessor().get_chain_fragment,
            self.request, self.view)

    def test_process_chain(self):
        self.assertTrue(ThreeRecursiveChainProcessor()
                        .process(self.request, self.view, obj="OBJ_SIMPLE_3"))
        self.assertFalse(TwoRecursiveChainProcessor()
                        .process(self.request, self.view, obj="OBJ_SIMPLE_2"))
