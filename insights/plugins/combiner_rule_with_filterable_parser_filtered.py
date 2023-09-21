from insights import rule, make_pass
from insights.core.filters import add_filter
from insights.combiners.cloud_provider import CloudProvider
from insights.parsers.rhsm_conf import RHSMConf

add_filter(RHSMConf, 'test')


@rule(CloudProvider, RHSMConf)
def combiner_with_filtered_filterable_parser(cp, rc):
    return make_pass("FAKE RESULT")
