from __future__ import unicode_literals

from django.dispatch import Signal

# to add additional chains, push onto the chain_generator array
# a function that takes a request, view, obj as arguments
get_additional_chains = Signal(providing_args=["processor", "chain_generator"])

get_additional_chain_fragments = Signal(
    providing_args=["processor", "fragments", "request", "view"]
)

process_additional_chain = Signal(
    providing_args=["processor", "chain", "result", "request", "view",
                    "obj", "validated_data"]
)