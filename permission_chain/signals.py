from __future__ import unicode_literals

from django.dispatch import Signal

get_additional_chains = Signal(
    providing_args=["chain_generator", "request", "view", "obj"]
)

get_additional_chain_fragments = Signal(providing_args=["fragments", "request",
                                                        "view"])

process_additional_chain = Signal(providing_args=["chain", "result",
                                                  "request", "view",
                                                  "obj", "validated_data"])