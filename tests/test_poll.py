import importlib.util
import os

spec = importlib.util.spec_from_file_location(
    "traxic_poll", os.path.join(os.path.dirname(__file__), "..", "externalscripts", "traxic_poll.py"))
poll = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poll)


def test_builtin_extend_oids():
    assert poll.builtin('NET-SNMP-EXTEND-MIB::nsExtendOutputFull."cpu_temp"') == \
        "1.3.6.1.4.1.8072.1.3.2.3.1.2.8." + ".".join(str(b) for b in b"cpu_temp")
    assert poll.builtin("nsExtendResult.3.1.2.3") == "1.3.6.1.4.1.8072.1.3.2.3.1.4.3.1.2.3"
    assert poll.builtin("MIKROTIK-MIB::mtxrSerialNumber.0") is None


def test_norm_and_clean():
    assert poll.norm_oid("get[.1.3.6.1.2.1.1.3.0]") == "1.3.6.1.2.1.1.3.0"
    assert poll._clean('"hello"') == "hello"
    assert poll._clean("No Such Object available on this agent at this OID") is None
