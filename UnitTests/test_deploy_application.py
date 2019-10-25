import deploy_application
import pytest
import ipaddress as ip

def test_generateSubnetsFromSeed_exists():
    with pytest.raises(ValueError, match="exists"):
        deploy_application.generateSubnetsFromSeed('test', ip.ip_network('10.46.10.0/24'))

@pytest.mark.parametrize("test_input,expected", [
    ("Alarm_Mgr_prod_client", "prod-client"),
    ("A_B_CCC_uat_deV", "uat-dev"),
    ("9_stg_db", 'stg-db'),
    ("9re7_stg_db", 'stg-db'),
])


def test_make_comment_1(test_input, expected):
    assert deploy_application.findBD(test_input) == expected