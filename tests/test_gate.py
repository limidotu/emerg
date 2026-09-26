import io

import pytest

from emergent_kali import runner_runtime
from emergent_kali.models import LAB, Limits
from emergent_kali.runner_runtime import Gate


def handler(gate, url):
    cls = gate.handler()
    value = cls.__new__(cls)
    value.path = url
    value.headers = {}
    value.command = "GET"
    value.wfile = io.BytesIO()
    value.responses_sent = []
    value.sent_headers = {}
    value.send_response = lambda code: value.responses_sent.append(code)
    value.send_error = lambda code, message: value.responses_sent.append(code)
    value.send_header = lambda key, val: value.sent_headers.update({key: val})
    value.end_headers = lambda: None
    return value


@pytest.mark.parametrize("url", ["http://example.com/", "http://127.0.0.1/", "http://juice-shop:3000@evil/"])
def test_gate_denies_before_network_call(tmp_path, monkeypatch, url):
    def network_forbidden(*args, **kwargs):
        pytest.fail("An out-of-scope URL reached the network.")

    monkeypatch.setattr(runner_runtime.http.client, "HTTPConnection", network_forbidden)
    value = handler(Gate(Limits().model_dump(), tmp_path), url)
    value.do_GET()
    assert value.responses_sent == [403]


def test_gate_drops_redirects_credentials_and_host_override(tmp_path, monkeypatch):
    calls = []

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("juice-shop", 3000)

        def request(self, method, target, headers):
            calls.append((method, target, headers))

        def getresponse(self):
            return self

        status = 302

        def read(self, maximum):
            return b"redirect"

        def getheaders(self):
            return [
                ("Location", "http://example.com"),
                ("Set-Cookie", "token=private"),
                ("Content-Type", "text/plain"),
            ]

        def close(self):
            pass

    monkeypatch.setattr(runner_runtime.http.client, "HTTPConnection", Connection)
    gate = Gate(Limits().model_dump(), tmp_path)
    value = handler(gate, LAB + "/")
    value.headers = {"Host": "example.com", "Authorization": "Bearer secret", "Cookie": "token=private"}
    value.do_GET()
    assert value.responses_sent == [302]
    assert "Location" not in value.sent_headers
    assert not {"Host", "Authorization", "Cookie"}.intersection(calls[0][2])
    assert "Set-Cookie" not in gate.records[0]["headers"]


@pytest.mark.parametrize("method", ["do_CONNECT", "do_POST"])
def test_gate_rejects_tunnels_and_post(tmp_path, method):
    value = handler(Gate(Limits().model_dump(), tmp_path), LAB)
    getattr(value, method)()
    assert value.responses_sent == [403]
