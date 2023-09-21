from insights import rule, make_pass
from insights.combiners.cloud_provider import CloudProvider


@rule(CloudProvider)
def combiner_wo_filterable_parser(cp):
    return make_pass("FAKE RESULT")
