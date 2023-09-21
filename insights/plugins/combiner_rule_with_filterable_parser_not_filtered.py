from insights import rule, make_pass
from insights.combiners.cloud_provider import CloudProvider
from insights.parsers.rhsm_conf import RHSMConf


@rule(CloudProvider, RHSMConf)
def combiner_with_no_filtered_filterable_parser(cp, rc):
    return make_pass("FAKE RESULT")
