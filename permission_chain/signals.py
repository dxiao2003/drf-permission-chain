from __future__ import unicode_literals

from django.dispatch import Signal

# to add additional chains, push onto the chain_generator array
# a function that takes a chain processor, request, view, obj as arguments
get_additional_chains = Signal(providing_args=["processor"])
"""
Receivers should return a function that takes (processor, request, view, obj)
and returns a chain.
"""

get_additional_chain_fragments = Signal(
    providing_args=["processor", "request", "view"]
)

process_additional_chain = Signal(
    providing_args=["processor", "chain", "request", "view", "obj",
                    "validated_data"]
)