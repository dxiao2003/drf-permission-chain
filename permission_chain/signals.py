from __future__ import unicode_literals

from django.dispatch import Signal

# to add additional chains, push onto the chain_generator array
# a function that takes a chain processor, request, view, obj as arguments
get_additional_chains = Signal(providing_args=["processor", "request", "view",
                                               "obj"])
"""
Receivers should return an iterator that produces chains.
"""

get_additional_chain_queries = Signal(
    providing_args=["processor", "request", "view"]
)

process_additional_chain = Signal(
    providing_args=["processor", "chain", "request", "view", "obj",
                    "validated_data"]
)