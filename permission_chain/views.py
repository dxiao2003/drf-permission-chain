from __future__ import unicode_literals

from rest_framework import status
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response


class ChainViewMixin(object):

    chain_permission_class = None
    """
    The ChainPermission subclass for this ChainProcessor.
    """

    @property
    def validated_data(self):
        return self.saved_serializer and self.saved_serializer.validated_data

    def get_object_without_permission_check(self):
        queryset = self.filter_queryset(self.get_queryset())

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
            'Expected view %s to be called with a URL keyword argument '
            'named "%s". Fix your URL conf, or set the `.lookup_field` '
            'attribute on the view correctly.' %
            (self.__class__.__name__, lookup_url_kwarg)
        )

        filter_kwargs = {self.lookup_field: self.kwargs[lookup_url_kwarg]}
        return get_object_or_404(queryset, **filter_kwargs)

    @property
    def saved_serializer(self):
        if not hasattr(self, "_saved_serializer"):
            if self.action == "create":
                serializer = self.get_serializer(data=self.request.data)
            elif self.action in ("update", "partial_update"):
                partial = self.action == "partial_update"
                instance = self.get_object_without_permission_check()
                serializer = self.get_serializer(instance,
                                                 data=self.request.data,
                                                 partial=partial)
            else:
                raise ValueError("View must be write action")

            serializer.is_valid(raise_exception=True)
            self._saved_serializer = serializer

        return self._saved_serializer

    def create(self, request, *args, **kwargs):
        serializer = self.saved_serializer
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED,
                        headers=headers)

    def update(self, request, *args, **kwargs):
        serializer = self.saved_serializer
        self.check_object_permissions(request, serializer.instance)
        self.perform_update(serializer)
        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def filter_queryset_by_chains(self, queryset, request, view=None):
        """
        Return a queryset filtered to only return objects that the user is
        allowed to view.
        """
        return queryset.filter(
            self.chain_permission.chain_processor
                .get_chain_fragment(request, view)
                .to_query_filter(request.user)
        ).distinct()

    @property
    def chain_permission(self):
        if not hasattr(self, "_chain_permission"):
            self._chain_permission = self.chain_permission_class()
        return self._chain_permission

    def filter_queryset(self, queryset):
        queryset = super(ChainViewMixin, self).filter_queryset(queryset)

        if self.chain_permission.skip_chain_filter(self.request, self):
            return queryset
        else:
            return self.filter_queryset_by_chains(
                queryset, self.request, self)

