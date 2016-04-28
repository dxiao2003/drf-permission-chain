from __future__ import unicode_literals

import itertools

from django.db.models import Q
from permission_chain.signals import get_additional_chains, \
    get_additional_chain_fragments, process_additional_chain
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import BasePermission
from rest_framework.response import Response

OBJECT_ACTIONS = ["retrieve", "update", "partial_update", "destroy"]

ALL_DJANGO_ACTIONS = {
    "create": "add",
    "update": "change",
    "partial_update": "change",
    "list": "view",
    "retrieve": "view",
    "destroy": "delete"
}


ALL_ACTION_NAMES = ALL_DJANGO_ACTIONS.keys()


def ConfigurablePermission(*args, **kwargs):

    django_action_map = kwargs.pop("django_actions", {})

    class CP(BasePermission):
        django_permission_pattern = kwargs.pop("django_permission_pattern",
                                               None)
        """
        A format string of the form ``"<app name>.%s_<model name>"`` where
        ``<app
        name>``
        and ``<model name>`` are the app and model names used to define the
        ``add``, ``change``, ``view``, and ``delete`` permissions on the model
        this permission is for.  Leave undefined if we should not grant access
        according to Django permissions.
        """

        django_actions = django_action_map
        """
        A list of actions that we should allow using the Django permissions
        model.
        Must be either "standard", a list of keys to the ALL_DJANGO_PERMS dic
        to include, or a dict mapping actions to corresponding
        Django permission type.  Actions not in this list
        will not be allowed using the Django permissions models.  For example,
        an entry in the standard list is "list": "view".

        A value of "standard" will include all standard actions.
        """
        if django_action_map == "standard":
            django_actions = ALL_DJANGO_ACTIONS
        elif isinstance(django_action_map, list):
            django_actions = {k: v for (k, v) in ALL_DJANGO_ACTIONS.items()
                              if k in django_action_map}
        elif not isinstance(django_action_map, dict):
            raise ValueError("Invalid setting for django_actions")

        staff_actions = kwargs.pop("staff_actions", [])
        """
        A list of actions that we should allow to users with ``is_staff`` set to
        ``True``.  Must be one of ``"create"``, ``"update"``,
        ``"partial_update"``,
        ``"list"``, ``"retrieve"``, ``"destroy"``.
        """
        if staff_actions == "standard":
            staff_actions = ALL_ACTION_NAMES

        unconstrained_actions = kwargs.pop("unconstrained_actions", [])
        """
        A list of actions that we should allow to anyone.
        Must be one of ``"create"``, ``"update"``, ``"partial_update"``,
        ``"list"``, ``"retrieve"``, ``"destroy"``.
        """
        if unconstrained_actions == "standard":
            staff_actions = ALL_ACTION_NAMES

        object_actions = \
            [a for a in OBJECT_ACTIONS
             if a in (django_actions.keys() + unconstrained_actions +
                      staff_actions)] + \
             kwargs.pop("additional_object_actions", [])

        def is_allowed_django_action(self, view, action):
            return view.action == action and \
                   action in self.django_actions.keys()

        def has_django_permission(self, request, view):
            if self.django_permission_pattern is None:
                return False

            for a in self.django_actions.keys():
                if self.is_allowed_django_action(view, a):
                    return request.user.has_perm(
                        self.django_permission_pattern % self.django_actions[a]
                    )

            return False

        def has_staff_permission(self, request, view):
            return view.action in self.staff_actions and request.user.is_staff

        def has_object_permission(self, request, view, obj):
            return view.action in self.unconstrained_actions or \
                   self.has_staff_permission(request, view) or \
                   self.has_django_permission(request, view)

        def has_permission(self, request, view):
            return view.action in self.object_actions or \
                   view.action in self.unconstrained_actions or \
                   self.has_staff_permission(request, view) or \
                   self.has_django_permission(request, view)

    return CP


def ChainPermission(*args, **kwargs):

    """
    List of object-level actions.  By default includes ``"retrieve"``,
    ``"update"``, ``"partial_update"``, ``"destroy"``.
    """

    base_permission_class = ConfigurablePermission(*args, **kwargs)

    chain_processor_class = kwargs.pop("chain_processor_class")

    chain_filter_actions = kwargs.pop("chain_filter_actions", ALL_ACTION_NAMES)

    class CP(base_permission_class):
        def __init__(self, *args, **kwargs):
            super(CP, self).__init__(*args, **kwargs)
            self.chain_processor = chain_processor_class()

        def has_chain_permission(self, request, view):
            if view.action == "create":
                return self.chain_processor.process(request, view)
            elif view.action == "list":
                # filtering allowed objects should occur in the viewset
                return "list" in chain_filter_actions or \
                       self.chain_processor.process(request, view)
            else:
                return False

        def has_chain_object_permission(self, request, view, obj):
            if view.action in self.object_actions:
                return self.chain_processor.process(request, view, obj)
            else:
                return False

        def has_object_permission(self, request, view, obj):
            return (super(CP, self).has_object_permission(request, view, obj) or
                    self.has_chain_object_permission(request, view, obj))

        def has_permission(self, request, view):
            return (super(CP, self).has_permission(request, view) or
                    self.has_chain_permission(request, view))

        def skip_chain_filter(self, request, view):
            return view.action in self.unconstrained_actions or \
                   self.has_django_permission(request, view) or \
                   self.has_staff_permission(request, view) or \
                   view.action not in chain_filter_actions

    return CP


class QueryFragment(object):
    OR = "OR"
    AND = "AND"
    CONST = "CONST"

    def __init__(self, *values, **kwargs):
        query_type = kwargs.pop("query_type", QueryFragment.CONST)

        if query_type in (QueryFragment.OR, QueryFragment.AND,
                          QueryFragment.CONST):
            self.query_type = query_type
        else:
            raise ValueError("Unknown query type: " + query_type)

        self.kwargs = kwargs

        if query_type == QueryFragment.CONST:
            if len(values) != 1 or not isinstance(values[0], basestring):
                raise ValueError("Constant fragment must consist of a single "
                                 "string")
            else:
                self.value = values[0]
        else:
            for v in values:
                if not isinstance(v, QueryFragment):
                    raise TypeError("Only QueryFragments allowed")

            self.values = set(values)

    def __and__(self, other):
        if not other:
            return self
        elif not isinstance(other, QueryFragment):
            raise ValueError("Cannot combine with non-QueryFragment")
        else:
            return QueryFragment(self, other, query_type=QueryFragment.AND)

    def __or__(self, other):
        if not other:
            return self
        elif not isinstance(other, QueryFragment):
            raise ValueError("Cannot combine with non-QueryFragment")
        else:
            return QueryFragment(self, other, query_type=QueryFragment.OR)

    def __eq__(self, other):
        if not isinstance(other, QueryFragment):
            return False
        elif self.query_type == QueryFragment.CONST and \
                        other.query_type == QueryFragment.CONST:
            return self.value == other.value
        elif self.query_type == other.query_type:
            return self.values == other.values
        else:
            return False

    def add_prefix(self, prefix):
        def prepend(old):
            return prefix + "__" + old
        return self.recursively_build(prepend)

    def recursively_build(self, func):
        if self.query_type == QueryFragment.CONST:
            return QueryFragment(func(self.value), query_type=self.query_type,
                                 **self.kwargs)
        else:
            return QueryFragment(
                *[v.recursively_build(func) for v in self.values],
                query_type=self.query_type,
                **self.kwargs
            )

    def to_query_filter(self, arg):
        if self.query_type == QueryFragment.CONST:
            if "fixed_arg" in self.kwargs:
                return Q(**{self.value: self.kwargs["fixed_arg"]})
            else:
                return Q(**{self.value: arg})
        elif self.query_type == QueryFragment.AND:
            filter = None
            for v in self.values:
                next_filter = v.to_query_filter(arg)
                if filter is None:
                    filter = next_filter
                else:
                    filter = filter & next_filter
            return filter
        elif self.query_type == QueryFragment.OR:
            filter = None
            for v in self.values:
                next_filter = v.to_query_filter(arg)
                if filter is None:
                    filter = next_filter
                else:
                    filter = filter | next_filter
            return filter


class ChainProcessor(object):

    def get_chains(self, request, view, obj=None):
        """
        Returns an iterator  of chains of permissions from ``request.user`` all
        the way to ``obj``.  Each chain is a tuple of elements representing a
        chain of permissions ``request.user`` to ``obj``
        The type and meaning of the elements in the chain are
        application-specific, but given knowledge of the chain it must be
        possible to determine whether the user in question has permission to
        perform some action on the object.  A "hypothetical" chain can be
        created for a ``"create"`` action where an object does not yet exist,
        since we may want to restrict which objects a user is allowed to create.
        """
        results = get_additional_chains.send_robust(self.__class__,
                                                    processor=self)
        for receiver, func in results:
            if hasattr(func, '__call__'):
                yield func(self, request, view, obj)

    def get_chain_fragment(self, request, view):
        result = get_additional_chain_fragments.send_robust(
            self.__class__, processor=self,
            request=request, view=view
        )
        if len(result) == 1:
            return result[0][1]
        elif len(result) > 1:
            fragments = [r[1] for r in result]
            return QueryFragment(*fragments, query_type=QueryFragment.OR)
        else:
            return None

    def process(self, request, view, obj=None):
        """
        Processes a chain to determine whether or not to authorize the action.
        Should return ``True`` if action is authorized and ``False`` otherwise.

        Either ``obj`` or ``data`` must be passed in, which specifies the start
        of the chain.
        """

        try:
            if view.action in ("create", "update", "partial_update"):
                validated_data = self.load_validated_data(request, view)
            else:
                validated_data = None

            for c in self.get_chains(request, view, obj):
                try:
                    if self.process_chain(c, request, view, obj,
                                          validated_data):
                        return True
                    else:
                        result = process_additional_chain.send_robust(
                            self.__class__, processor=self,
                            chain=c, request=request, view=view, obj=obj,
                            validated_data=validated_data)
                        if any([r[1] == True for r in result]):
                            return True
                except:
                    pass
        except ValidationError:
            raise
        except:
            return False

        return False

    def process_chain(self, chain, request, view, obj=None,
                      validated_data=None):
        return False

    def load_validated_data(self, request, view):
        if view.action not in ("create", "update", "partial_update"):
            raise ValueError("Must be called with a write operation")
        else:
            return view.validated_data


class RecursiveChainProcessor(ChainProcessor):
    """
    A recursive implementation of ``ChainProcessor``.  Each
    ``RecursiveChainProcessor`` is connected to another ``ChainProcessor``
    that is one step closer to the user.  This simplifies implementation since
    we only need to add one link to the chain.
    """

    next_chain_processor_class = None
    next_chain_processor_kwargs = {}

    def __init__(self, *args, **kwargs):
        super(RecursiveChainProcessor, self).__init__(*args, **kwargs)
        self.next_chain_processor = self.next_chain_processor_class(
            **self.next_chain_processor_kwargs
        )
    def get_chains(self, request, view, obj=None):
        return itertools.chain(
            self.get_recursive_chains(request, view, obj),
            super(RecursiveChainProcessor, self).get_chains(request, view,
                                                            obj=obj)
            )

    def get_recursive_chains(self, request, view, obj=None):
        """
        Gets a permission chain by first finding all links to the next
        step in the chain, then calling the chain processor for the next links.

        :returns a list of chains, each chain is a tuple of the form
                 ``(object, relationship)`` where ``relationship`` is
                 application-specific data about how ``object`` relates to the
                 next step in the chain
        """

        next_links = self.get_next_links(request, view, obj)

        for l in next_links:
            next_chains = self.next_chain_processor.get_chains(
                request, view, l)
            for c in next_chains:
                yield c + (l,)

    def get_next_links(self, request, view, obj=None):
        """
        Return a list of possible next links in the chain.  Each link is a
        ``(next_obj, relationship)`` tuple, where ``next_obj`` is the next
        object and ``relationship`` is application-specific data specifying
        how this ``obj`` is related to ``next_obj``.

        If the action is ``create``, then ``obj`` may be None and the processor
        must extract a hypothetical object from the request data and find
        the next link with respect to the hypothetical object.
        """
        raise NotImplementedError

    def get_chain_fragment(self, request, view):
        fragment = super(RecursiveChainProcessor, self).get_chain_fragment(
            request, view)
        try:
            return self.recursive_chain_fragment(request, view) | fragment
        except InvalidChainException:
            if fragment is not None:
                return fragment
            else:
                raise

    def recursive_chain_fragment(self, request, view):
        next_prefixes = self.next_link_chain_prefixes(request, view)
        recursive_fragment = \
            self.next_chain_processor.get_chain_fragment(request, view)

        updated_fragments = []

        for f in next_prefixes:
            updated_fragments.append(recursive_fragment.add_prefix(f))

        if len(updated_fragments) > 1:
            return QueryFragment(*updated_fragments,
                                 query_type=QueryFragment.OR)
        elif len(updated_fragments) == 1:
            return updated_fragments[0]
        else:
            raise InvalidChainException("No prefixes found")

    def next_link_chain_prefixes(self, request, view):
        """
        :returns A list of strings that can be used as prefixes to
                 QueryFragments.
        """
        raise NotImplementedError


class InvalidChainException(PermissionDenied):
    pass