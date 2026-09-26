import json

from emergent_kali.runner_runtime import command
from emergent_kali.signatures import (
    LAB_ORIGIN,
    START_PATHS,
    SURFACE_PATHS,
    detect,
    echoed_account,
    mentioned_paths,
)


def test_surface_paths_pass_the_command_policy():
    argv = command(
        "content_discovery",
        {"url": LAB_ORIGIN, "paths": list(SURFACE_PATHS), "max_pages": 20, "ports": [3000]},
        {"requests_per_second": 2, "command_seconds": 90, "output_bytes": 524288},
    )
    assert "http_walk" in argv
    assert len(SURFACE_PATHS) <= 20


def test_confidential_document_matches_its_own_url():
    found = detect(
        {
            "url": "http://juice-shop:3000/ftp/acquisitions.md",
            "status": 200,
            "body": "This document is confidential! Do not distribute!",
        }
    )
    assert [item["title"] for item in found] == ["Confidential Document"]
    assert found[0]["quote"] == "This document is confidential!"


def test_same_sentence_on_another_url_is_ignored():
    assert (
        detect(
            {
                "url": "http://juice-shop:3000/ftp/",
                "status": 200,
                "body": "This document is confidential!",
            }
        )
        == []
    )


def test_blocked_backup_needs_the_403_status():
    body = "Error: Only .md and .pdf files are allowed!"
    url = "http://juice-shop:3000/ftp/package.json.bak"
    assert detect({"url": url, "status": 200, "body": body}) == []
    found = detect({"url": url, "status": 403, "body": body})
    assert found[0]["title"] == "Blocked file name returns a detailed error"


def test_unexpected_path_is_error_handling():
    found = detect(
        {
            "url": "http://juice-shop:3000/rest/qwertz",
            "status": 500,
            "body": "<title>Error: Unexpected path: /rest/qwertz</title>",
        }
    )
    assert found[0]["title"] == "Error Handling"


def test_empty_registration_matches_only_a_created_account():
    body = '{"status":"success","data":{"role":"customer"}}'
    assert detect({"url": "http://juice-shop:3000/api/Users", "status": 400, "body": body}) == []
    found = detect({"url": "http://juice-shop:3000/api/Users", "status": 201, "body": body})
    assert found[0]["title"] == "Empty User Registration"


def test_client_script_names_three_routes():
    body = 'F("score-board") F("privacy-security/privacy-policy") Maybe /administration will work?'
    found = detect({"url": "http://juice-shop:3000/main.js", "status": 200, "body": body})
    assert {item["title"] for item in found} == {"Score Board", "Privacy Policy", "Admin Section"}


def test_listing_links_keep_logs_and_skip_keys():
    from emergent_kali.signatures import child_paths

    children = child_paths(
        {
            "url": "http://juice-shop:3000/support/logs/",
            "status": 200,
            "body": (
                '<title>listing directory /support/logs/</title>'
                '<a href="access.log.2026-09-24"></a>'
                '<a href="./.."></a><a href="premium.key"></a>'
            ),
        }
    )
    assert children == ["/support/logs/access.log.2026-09-24"]


def test_access_log_quotes_a_request_line():
    found = detect(
        {
            "url": "http://juice-shop:3000/support/logs/access.log.2026-09-24",
            "status": 200,
            "body": '::1 - - [24/Sep/2026] "GET /robots.txt HTTP/1.1" 200\n',
        }
    )
    assert found[0]["title"] == "Access Log"
    assert found[0]["quote"] == '"GET /robots.txt HTTP/1.1"'


def test_any_listing_title_is_a_directory_finding():
    found = detect(
        {
            "url": "http://juice-shop:3000/support/logs/",
            "status": 200,
            "body": "<title>listing directory /support/logs/</title>",
        }
    )
    assert found[0]["title"] == "Public directory listing"
    assert found[0]["quote"] == "<title>listing directory /support/logs/</title>"


def test_unencoded_memory_path_is_missing_encoding():
    found = detect(
        {
            "url": "http://juice-shop:3000/rest/memories",
            "status": 200,
            "body": '{"caption":"photo-marker","imagePath":"cat-\u2603-file"}',
        }
    )
    assert any(item["title"] == "Missing Encoding" for item in found)


def test_jwt_rule_uses_the_rsa_header():
    found = detect(
        {
            "url": "http://juice-shop:3000/encryptionkeys/jwt.pub",
            "status": 200,
            "body": "-----BEGIN RSA PUBLIC KEY-----\n[key omitted]\n-----END RSA PUBLIC KEY-----",
        }
    )
    assert found[0]["title"] == "JWT verification key is public"
    assert found[0]["quote"] == "-----BEGIN RSA PUBLIC KEY-----"


def test_clip_evidence_keeps_a_short_excerpt():
    from emergent_kali.engine import clip_evidence

    clipped = clip_evidence(
        {
            "ev-1": {
                "tool": "content_discovery",
                "stdout": "x" * 5000,
                "exit_code": 0,
                "truncated": False,
                "records": [
                    {"url": "http://juice-shop:3000/metrics", "status": 200, "headers": {}, "body": "y" * 2000}
                ],
            }
        }
    )
    assert "stdout" not in clipped["ev-1"]
    assert len(clipped["ev-1"]["records"][0]["body"]) == 1500


def test_clip_evidence_omits_a_source_map_body():
    from emergent_kali.engine import clip_evidence

    clipped = clip_evidence(
        {
            "ev-1": {
                "tool": "content_discovery",
                "exit_code": 0,
                "truncated": False,
                "records": [
                    {
                        "url": "http://juice-shop:3000/ui/app.js.map",
                        "status": 200,
                        "body": '{"sourcesContent":["library"]}',
                    },
                    {
                        "url": "http://juice-shop:3000/api/Users",
                        "status": 200,
                        "body": '{"email":"a@b.c"}',
                    },
                ],
            }
        }
    )
    urls = [record["url"] for record in clipped["ev-1"]["records"]]
    assert urls == ["http://juice-shop:3000/api/Users"]


def test_clip_evidence_omits_script_stylesheet_and_image_bodies():
    from emergent_kali.engine import clip_evidence

    clipped = clip_evidence(
        {
            "ev-1": {
                "tool": "content_discovery",
                "exit_code": 0,
                "truncated": False,
                "records": [
                    {"url": "http://juice-shop:3000/ui/app.js", "status": 200, "body": "function library(){}"},
                    {"url": "http://juice-shop:3000/ui/app.css", "status": 200, "body": ".library{color:red}"},
                    {"url": "http://juice-shop:3000/ui/icon.png", "status": 200, "body": "PNG"},
                    {"url": "http://juice-shop:3000/api/Users", "status": 200, "body": '{"email":"a@b.c"}'},
                ],
            }
        }
    )
    urls = [record["url"] for record in clipped["ev-1"]["records"]]
    assert urls == ["http://juice-shop:3000/api/Users"]


def test_clip_evidence_omits_an_api_document_body():
    from emergent_kali.engine import clip_evidence

    clipped = clip_evidence(
        {
            "ev-1": {
                "tool": "content_discovery",
                "exit_code": 0,
                "truncated": False,
                "records": [
                    {
                        "url": "http://juice-shop:3000/openapi.json",
                        "status": 200,
                        "body": '{"openapi":"3.0.0","paths":{"/users":{"get":{}}}}',
                    },
                    {
                        "url": "http://juice-shop:3000/api/Users",
                        "status": 200,
                        "body": '{"email":"a@b.c"}',
                    },
                ],
            }
        }
    )
    urls = [record["url"] for record in clipped["ev-1"]["records"]]
    assert urls == ["http://juice-shop:3000/api/Users"]


def test_clip_evidence_omits_an_html_page_body():
    from emergent_kali.engine import clip_evidence

    clipped = clip_evidence(
        {
            "ev-1": {
                "tool": "content_discovery",
                "exit_code": 0,
                "truncated": False,
                "records": [
                    {
                        "url": "http://juice-shop:3000/ui/",
                        "status": 200,
                        "body": "<!DOCTYPE html><html><body>library</body></html>",
                    },
                    {
                        "url": "http://juice-shop:3000/api/Users",
                        "status": 200,
                        "body": '{"email":"a@b.c"}',
                    },
                ],
            }
        }
    )
    urls = [record["url"] for record in clipped["ev-1"]["records"]]
    assert urls == ["http://juice-shop:3000/api/Users"]


def test_start_paths_are_not_a_prior_finding_list():
    assert "/ftp/" not in START_PATHS
    assert "/api/Users" not in START_PATHS
    assert START_PATHS[0] == "/"
    assert "/.well-known/security.txt" in START_PATHS
    assert START_PATHS[START_PATHS.index("/robots.txt") + 1] == "/.well-known/security.txt"
    assert "/.env" in START_PATHS
    assert "/.env.bak" not in START_PATHS


def test_openapi_document_names_readable_paths():
    body = (
        '{"openapi":"3.0.0","paths":{"/users/v1":{"get":{}},"/createdb":{"get":{}},'
        '"/users/v1/{username}":{"get":{}},"learning/teaching":{"get":{}}}}'
    )
    assert mentioned_paths({"url": LAB_ORIGIN + "/openapi.json", "body": body}) == [
        "/users/v1",
        "/createdb",
    ]


def test_prose_with_a_slash_is_not_a_path():
    body = '{"help":"It can be used in learning/teaching purposes."}'
    assert mentioned_paths({"url": LAB_ORIGIN + "/", "body": body}) == []


def test_a_script_quotes_an_absolute_path():
    body = 'var base = "/files/notes.txt"; var note = "learning/teaching"; var css = "/ui/app.css";'
    assert mentioned_paths({"url": LAB_ORIGIN + "/ui/app.js", "body": body}) == [
        "/files/notes.txt",
        "/ui/app.css",
    ]
    assert mentioned_paths({"url": LAB_ORIGIN + "/ui/", "body": body}) == []


def test_a_script_names_its_sibling_source_map(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import sibling_map_path

    assert sibling_map_path("http://vampi:5000/ui/app.js") == "/ui/app.js.map"
    assert sibling_map_path("http://vampi:5000/ui/app.css") == "/ui/app.css.map"
    assert sibling_map_path("http://vampi:5000/ui/app.js.map") == ""
    assert sibling_map_path("http://vampi:5000/users/v1") == ""
    body = '{"email":"ada@example.com","password":"present"}'
    found = detect({"url": "http://vampi:5000/ui/app.js.map", "status": 200, "body": body})
    assert all(item["title"] != "Public response includes a secret field" for item in found)
    assert all(item["title"] != "Public response lists an email address" for item in found)
    plain = detect({"url": "http://vampi:5000/users/v1", "status": 200, "body": body})
    assert any(item["title"] == "Public response lists an email address" for item in plain)


def test_a_json_value_that_is_exactly_a_path_is_read():
    from emergent_kali.signatures import exact_path_values

    body = '{"next":"/users/v1/profile","help":"See /guide for the notes.","note":"learning/teaching"}'
    assert exact_path_values(body) == ["/users/v1/profile"]
    assert "/users/v1/profile" in mentioned_paths({"url": LAB_ORIGIN + "/", "body": body})
    assert exact_path_values('{"bad":"/drop","also":"/password","note":"See /guide"}') == []
    spec = '{"openapi":"3.0.1","paths":{"/books/v1":{"get":{}}},"example":"/hidden/file"}'
    assert "/hidden/file" not in mentioned_paths({"url": LAB_ORIGIN + "/openapi.json", "body": spec})


def test_a_json_string_names_one_segment_path():
    from emergent_kali.signatures import named_segment_paths

    assert named_segment_paths('{"docs":"/guide"}') == ["/guide"]
    assert mentioned_paths({"url": LAB_ORIGIN + "/", "body": '{"help":"See /guide for the notes."}'}) == [
        "/guide"
    ]
    assert named_segment_paths('{"help":"Visit http://lab.example/guide today"}') == []
    assert named_segment_paths('{"path":"/users/v1"}') == []
    assert named_segment_paths('{"help":"It can be used in learning/teaching purposes."}') == []
    assert named_segment_paths("<html>See /guide</html>") == []
    spec = '{"openapi":"3.0.1","paths":{"/createdb":{"get":{}},"/books/v1":{"get":{}}}}'
    assert "/createdb" not in [
        path for path in mentioned_paths({"url": LAB_ORIGIN + "/openapi.json", "body": spec}) if path == "/guide"
    ]
    assert mentioned_paths({"url": LAB_ORIGIN + "/openapi.json", "body": spec}) == ["/createdb", "/books/v1"]


def test_broken_spec_still_names_readable_paths():
    body = (
        '{"openapi":"3.0.1","paths":{"/books/v1":{"get":{}},"/createdb":{"get":{}},'
        '"/users/v1":{"get":{"secret": [REDACTED] "type":"string"}},'
        '"/users/v1/{id}":{"get":{}}}}'
    )
    assert mentioned_paths({"url": LAB_ORIGIN + "/openapi.json", "body": body}) == [
        "/books/v1",
        "/createdb",
        "/users/v1",
    ]


def test_post_only_and_destructive_paths_stay_unread():
    body = (
        '{"openapi":"3.0.1","paths":{"/users/v1/login":{"post":{}},'
        '"/drop":{"get":{}},"/books/v1":{"get":{}}}}'
    )
    assert mentioned_paths({"url": LAB_ORIGIN + "/openapi.json", "body": body}) == ["/books/v1"]


def test_setup_get_is_read_before_other_paths():
    from emergent_kali.signatures import priority_paths

    body = (
        '{"openapi":"3.0.1","paths":{"/books/v1":{"get":{"description":"Retrieves all books"}},'
        '"/createdb":{"get":{"description":"Creates and populates the database with dummy data"}}}}'
    )
    assert priority_paths(body) == ["/createdb"]


def test_public_user_record_quotes_the_secret_field_and_the_email(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = '{"users":[{"email":"mail1@mail.com","password":"[REDACTED]","username":"name1"}]}'
    titles = [
        item["title"]
        for item in detect({"url": "http://vampi:5000/users/v1/_debug", "status": 200, "body": body})
    ]
    assert titles == [
        "Public response includes a secret field",
        "Public response lists an email address",
    ]


def test_a_response_value_fills_one_documented_placeholder(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import concrete_paths, secured_reads

    spec = """
    {
      "openapi": "3.0.1",
      "paths": {
        "/books/v1/{book_title}": {"get": {"security": [{"bearerAuth": []}]}},
        "/users/v1/{username}": {"get": {"responses": {"200": {}}}}
      }
    }
    """
    records = [
        {
            "url": LAB_ORIGIN + "/books/v1",
            "status": 200,
            "body": '{"Books":[{"book_title":"bookTitle77","user":"name1"}]}',
        }
    ]
    assert concrete_paths(spec, records) == ["/books/v1/bookTitle77"]
    found = secured_reads(
        spec,
        {
            "url": "http://vampi:5000/books/v1/bookTitle77",
            "status": 200,
            "body": '{"secret":"[REDACTED]","book_title":"bookTitle77"}',
        },
    )
    assert found[0]["title"] == "A protected record is public"
    assert found[0]["quote"] == '"secret":'


def test_one_placeholder_uses_sixteen_copied_values():
    from emergent_kali.signatures import concrete_paths

    titles = ",".join(f'{{"book_title":"bookTitle{index:02d}"}}' for index in range(17))
    spec = '{"openapi":"3.0.1","paths":{"/books/v1/{book_title}":{"get":{}}}}'
    body = '{"Books":[' + titles + "]}"
    found = concrete_paths(spec, [{"url": "http://vampi:5000/books/v1", "body": body}])
    assert len(found) == 16
    assert found[0] == "/books/v1/bookTitle00"
    assert "/books/v1/bookTitle16" not in found


def test_a_json_number_fills_only_the_matching_placeholder(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import concrete_paths

    spec = '{"openapi":"3.0.1","paths":{"/items/{id}":{"get":{}},"/status/{status}":{"get":{}}}}'
    records = [{"url": "http://vampi:5000/items", "status": 200, "body": '{"id": 7, "status": 404}'}]
    assert concrete_paths(spec, records) == ["/items/7", "/status/404"]
    assert "/items/404" not in concrete_paths(spec, records)


def test_a_named_path_that_was_not_fetched_stays_unread(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import unread_paths

    spec = '{"openapi":"3.0.1","paths":{"/books/v1":{"get":{}},"/extra":{"get":{}}}}'
    records = [{"url": "http://vampi:5000/openapi.json", "body": spec}]
    assert unread_paths(records, spec, {"http://vampi:5000/openapi.json"}, "http://vampi:5000") == [
        "/books/v1",
        "/extra",
    ]


def test_every_listed_identifier_is_queued(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import concrete_paths

    spec = """
    {"openapi":"3.0.1","paths":{"/books/v1/{book_title}":{"get":{}}}}
    """
    body = '{"Books":[{"book_title":"bookTitle1"},{"book_title":"bookTitle2"},{"book_title":"bookTitle3"}]}'
    assert concrete_paths(spec, [{"url": "http://vampi:5000/books/v1", "body": body}]) == [
        "/books/v1/bookTitle1",
        "/books/v1/bookTitle2",
        "/books/v1/bookTitle3",
    ]


def test_a_middle_placeholder_is_filled(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import concrete_paths

    spec = """
    {"openapi":"3.0.1","paths":{
      "/items/{id}/reviews":{"get":{}},
      "/items/{id}/notes/{name}":{"get":{}},
      "/admin/{id}":{"post":{}},
      "/accounts/{id}/password":{"get":{}}
    }}
    """
    records = [{"url": "http://vampi:5000/items", "status": 200, "body": '{"id":"7"}'}]
    assert concrete_paths(spec, records) == ["/items/7/reviews"]


def test_two_placeholders_fill_only_when_each_name_has_one_value(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import concrete_paths

    spec = """
    {"openapi":"3.0.1","paths":{
      "/items/{id}/notes/{name}":{"get":{}},
      "/skip/{id}/{name}":{"post":{}},
      "/accounts/{user}/password/{name}":{"get":{}}
    }}
    """
    one = [{"url": "http://vampi:5000/items", "status": 200, "body": '{"id":"7","name":"ada","user":"ada"}'}]
    assert concrete_paths(spec, one) == ["/items/7/notes/ada"]
    many = [
        {"url": "http://vampi:5000/items", "status": 200, "body": '{"id":"7","name":"ada"}'},
        {"url": "http://vampi:5000/items", "status": 200, "body": '{"id":"8"}'},
    ]
    assert concrete_paths(spec, many) == []


def test_a_public_get_is_not_treated_as_a_protected_record(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.signatures import secured_reads

    spec = """
    {
      "openapi": "3.0.1",
      "paths": {
        "/users/v1/{username}": {
          "delete": {"security": [{"bearerAuth": []}]},
          "get": {"responses": {"200": {}}}
        },
        "/users/v1/_debug": {"get": {"responses": {"200": {}}}}
      }
    }
    """
    assert (
        secured_reads(
            spec,
            {
                "url": "http://vampi:5000/users/v1/name1",
                "status": 200,
                "body": '{"username":"name1","email":"mail1@mail.com"}',
            },
        )
        == []
    )
    assert (
        secured_reads(
            spec,
            {
                "url": "http://vampi:5000/users/v1/_debug",
                "status": 200,
                "body": '{"password":"[REDACTED]"}',
            },
        )
        == []
    )


def test_another_account_can_read_a_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    def fake(method, path, payload=None, headers=None):
        if method == "POST":
            return 200, '{"auth_token":"token-value-1"}'
        return 200, '{"user":"name2","secret":"hidden-value"}'

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": (
            '{"openapi":"3.0.1","paths":{"/users/v1/login":{"post":{}},'
            '"/books/v1/{book_title}":{"get":{"security":[{"bearerAuth":[]}]}}}}'
        ),
    }
    debug = {
        "url": "http://vampi:5000/users/v1/_debug",
        "status": 200,
        "body": '{"users":[{"username":"name1","password":"pw-one"},{"username":"name2","password":"pw-two"}]}',
    }
    books = {
        "url": "http://vampi:5000/books/v1",
        "status": 200,
        "body": '{"Books":[{"book_title":"bookTitle77","user":"name2"}]}',
    }
    denied = {"url": "http://vampi:5000/books/v1/bookTitle77", "status": 401, "body": "{}"}
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    assert session_follow([spec, debug, books], *paths) == []
    extra = session_follow([denied], *paths)
    assert extra[0]["headers"]["X-Emerg-Actor"] == "name1"
    assert [item["title"] for item in detect(extra[0])] == ["Another account can read this secret"]


def test_an_earlier_401_is_retried_after_a_session_exists(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    def fake(method, path, payload=None, headers=None):
        if method == "POST":
            return 200, '{"auth_token":"token-value-1"}'
        return 200, '{"username":"name1","email":"name1@mail.com"}'

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": (
            '{"openapi":"3.0.1","paths":{"/users/v1/login":{"post":{}},'
            '"/me":{"get":{"security":[{"bearerAuth":[]}]}}}}'
        ),
    }
    denied = {"url": "http://vampi:5000/me", "status": 401, "body": "{}"}
    debug = {
        "url": "http://vampi:5000/users/v1/_debug",
        "status": 200,
        "body": '{"users":[{"username":"name1","password":"pw-one"}]}',
    }
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    assert session_follow([spec, denied], *paths) == []
    extra = session_follow([debug], *paths)
    assert extra[0]["url"].endswith("/me")
    assert extra[0]["headers"]["X-Emerg-Actor"] == "name1"
    opened = {"url": "http://vampi:5000/me", "status": 200, "body": "{}"}
    assert session_follow([opened], *paths) == []


def test_write_checks_do_not_consume_the_retry_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    def fake(method, path, payload=None, headers=None):
        if method == "POST" and str(path).endswith("login"):
            password = str((payload or {}).get("password") or "")
            user = str((payload or {}).get("username") or "")
            if password == "pw-one" or password.endswith("x"):
                return 200, '{"auth_token":"token-value-1","message":"Successfully logged in."}'
            if user == "absent-user":
                return 200, '{"message":"Username does not exist."}'
            return 200, '{"message":"Password is not correct for the given username."}'
        if method == "POST":
            return 200, '{"message":"Registered"}'
        if method == "PUT":
            return 204, ""
        return 200, '{"user":"name2","secret":"hidden-value"}'

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": json.dumps(
            {
                "openapi": "3.0.1",
                "paths": {
                    "/users/v1/login": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"properties": {"username": {}, "password": {}}}
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/register": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {"username": {}, "password": {}, "email": {}}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/{username}/password": {
                        "put": {
                            "requestBody": {
                                "content": {"application/json": {"schema": {"properties": {"password": {}}}}}
                            }
                        }
                    },
                    "/books/v1/{book_title}": {"get": {"security": [{"bearerAuth": []}]}},
                },
            }
        ),
    }
    debug = {
        "url": "http://vampi:5000/users/v1/_debug",
        "status": 200,
        "body": '{"users":[{"username":"name1","password":"pw-one"}]}',
    }
    books = {
        "url": "http://vampi:5000/books/v1",
        "status": 200,
        "body": json.dumps(
            {"Books": [{"book_title": f"bookTitle{index:02d}", "user": "name2"} for index in range(8)]}
        ),
    }
    denied = [
        {"url": f"http://vampi:5000/books/v1/bookTitle{index:02d}", "status": 401, "body": "{}"}
        for index in range(8)
    ]
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    extra = session_follow([spec, debug, books, *denied], *paths)
    books_read = [item for item in extra if "/books/v1/bookTitle" in str(item.get("url"))]
    assert len(books_read) == 8
    assert any((item.get("headers") or {}).get("X-Emerg-Write") == "1" for item in extra)


def test_a_public_password_can_read_an_account_page(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    def fake(method, path, payload=None, headers=None):
        if method == "POST":
            return 200, '{"auth_token":"token-value-1"}'
        return 200, '{"username":"name1","email":"name1@mail.com"}'

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": (
            '{"openapi":"3.0.1","paths":{"/users/v1/login":{"post":{}},'
            '"/me":{"get":{"security":[{"bearerAuth":[]}]}}}}'
        ),
    }
    debug = {
        "url": "http://vampi:5000/users/v1/_debug",
        "status": 200,
        "body": '{"users":[{"username":"name1","password":"pw-one"}]}',
    }
    denied = {"url": "http://vampi:5000/me", "status": 401, "body": "{}"}
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    assert session_follow([spec, debug], *paths) == []
    extra = session_follow([denied], *paths)
    assert extra[0]["headers"]["X-Emerg-Actor"] == "name1"
    hits = [item for item in detect(extra[0]) if item["title"] == "A public password can read this account"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "name1@mail.com"
    assert hits[0]["quote"] in extra[0]["body"]


def test_another_account_can_change_a_password(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    def fake(method, path, payload=None, headers=None):
        if method == "POST" and path.endswith("login"):
            password = (payload or {}).get("password", "")
            if password == "pw-one" or str(password).endswith("x"):
                return 200, '{"auth_token":"token-value-1","message":"Successfully logged in.","status":"success"}'
            return 200, '{"message":"Password is not correct for the given username.","status":"fail"}'
        if method == "POST":
            return 200, '{"message":"Registered","status":"success"}'
        if method == "PUT":
            return 204, ""
        return 401, "{}"

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": json.dumps(
            {
                "openapi": "3.0.1",
                "paths": {
                    "/users/v1/login": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"properties": {"username": {}, "password": {}}}
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/register": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {"username": {}, "password": {}, "email": {}}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/{username}/password": {
                        "put": {
                            "requestBody": {
                                "content": {"application/json": {"schema": {"properties": {"password": {}}}}}
                            }
                        }
                    },
                },
            }
        ),
    }
    debug = {
        "url": "http://vampi:5000/users/v1/_debug",
        "status": 200,
        "body": '{"users":[{"username":"name1","password":"pw-one"}]}',
    }
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    session_follow([spec], *paths)
    extra = session_follow([debug], *paths)
    hits = [item for item in extra if (item.get("headers") or {}).get("X-Emerg-Write") == "1"]
    assert len(hits) == 1
    from emergent_kali.redaction import redact

    stored = redact(hits[0])
    found = [item for item in detect(stored) if item["title"] == "Another account can change this password"]
    assert len(found) == 1
    assert found[0]["quote"] == "correct for the given username."
    assert found[0]["quote"] in stored["body"]
    assert "auth_token" not in stored["body"]
    assert found[0]["location"].endswith("/users/v1/login")
    assert found[0]["reproduction"][0].startswith("PUT /users/v1/")
    assert found[0]["reproduction"][0].endswith("/password")
    refused = detect(
        {
            "url": "http://vampi:5000/users/v1/e123/password",
            "status": 200,
            "headers": {"X-Emerg-Write": "1"},
            "body": '{"message":"Update failed for account"}',
        }
    )
    assert all(item["title"] != "Another account can change this password" for item in refused)


def test_another_account_can_delete_a_fresh_account(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    deleted = []

    def fake(method, path, payload=None, headers=None):
        if method == "POST" and path.endswith("login"):
            user = (payload or {}).get("username", "")
            token = "token-admin" if user == "admin" else "token-value-1"
            return 200, json.dumps({"auth_token": token, "message": "Successfully logged in."})
        if method == "POST":
            return 200, '{"message":"Registered","status":"success"}'
        if method == "DELETE":
            deleted.append((path, (headers or {}).get("Authorization")))
            return 200, '{"status":"success","message":"User deleted."}'
        return 401, "{}"

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": json.dumps(
            {
                "openapi": "3.0.1",
                "paths": {
                    "/users/v1/login": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"properties": {"username": {}, "password": {}}}
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/register": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {"username": {}, "password": {}, "email": {}}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/{username}": {"delete": {}},
                    "/books/v1/{book_title}": {"delete": {}},
                },
            }
        ),
    }
    debug = {
        "url": "http://vampi:5000/users/v1/_debug",
        "status": 200,
        "body": json.dumps(
            {
                "users": [
                    {"username": "admin", "password": "pw-admin", "admin": True},
                    {"username": "name1", "password": "pw-one", "admin": False},
                ]
            }
        ),
    }
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    session_follow([spec], *paths)
    extra = session_follow([debug], *paths)
    hits = [item for item in extra if (item.get("headers") or {}).get("X-Emerg-Delete") == "1"]
    assert len(hits) == 1
    assert deleted[0][0].startswith("/users/v1/e")
    assert deleted[0][1] == "Bearer token-value-1"
    assert "admin" not in deleted[0][0]
    found = [item for item in detect(hits[0]) if item["title"] == "Another account can delete this account"]
    assert len(found) == 1
    assert found[0]["quote"] == "User deleted."
    assert found[0]["quote"] in hits[0]["body"]
    assert "@" not in hits[0]["body"]
    assert found[0]["reproduction"][0].startswith("DELETE /users/v1/e")
    refused = detect(
        {
            "url": "http://vampi:5000/users/v1/e12345678",
            "status": 401,
            "headers": {"X-Emerg-Delete": "1"},
            "body": '{"message":"Only Admins may delete users!"}',
        }
    )
    assert all(item["title"] != "Another account can delete this account" for item in refused)


def test_a_registered_admin_flag_is_on_the_account_page(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    def fake(method, path, payload=None, headers=None):
        if method == "POST" and path.endswith("register"):
            assert (payload or {}).get("admin") is True
            return 200, '{"message":"Registered"}'
        if method == "POST" and path.endswith("login"):
            return 200, '{"auth_token":"token-value-1","message":"Successfully logged in."}'
        if method == "GET" and path == "/me":
            assert (headers or {}).get("Authorization", "").startswith("Bearer ")
            return 200, '{"data":{"email":"e@example.com","username":"e1","admin": true}}'
        if "debug" in path:
            raise AssertionError(path)
        return 404, "{}"

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": json.dumps(
            {
                "openapi": "3.0.1",
                "paths": {
                    "/users/v1/login": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"properties": {"username": {}, "password": {}}}
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/register": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {"username": {}, "password": {}, "email": {}}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "/me": {
                        "get": {
                            "security": [{"bearerAuth": []}],
                            "responses": {
                                "200": {
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "properties": {
                                                    "data": {"properties": {"admin": {}, "email": {}}}
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                        }
                    },
                    "/users/v1/_debug": {
                        "get": {
                            "responses": {
                                "200": {
                                    "content": {
                                        "application/json": {
                                            "schema": {"properties": {"admin": {}}}
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            }
        ),
    }
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    extra = session_follow([spec], *paths)
    hits = [item for item in extra if item.get("body") == '"admin": true']
    assert len(hits) == 1
    assert hits[0]["url"].endswith("/me")
    assert "email" not in hits[0]["body"]
    found = detect(hits[0])
    assert [item["title"] for item in found] == ["Public response shows an admin flag"]
    assert found[0]["quote"] == '"admin": true'
    assert found[0]["location"].endswith("/me")


def test_another_account_can_change_an_email(monkeypatch, tmp_path):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    from emergent_kali.runner_runtime import session_follow

    seen = {"email": ""}

    def fake(method, path, payload=None, headers=None):
        if method == "POST" and path.endswith("login"):
            if (payload or {}).get("password") == "pw-one":
                return 200, '{"auth_token":"token-value-1"}'
            return 401, "{}"
        if method == "POST":
            return 200, '{"message":"Registered"}'
        if method == "PUT":
            seen["email"] = str((payload or {}).get("email") or "")
            return 204, ""
        if method == "GET" and "/users/v1/" in path and "debug" not in path:
            user = path.rsplit("/", 1)[-1]
            return 200, json.dumps({"email": seen["email"], "username": user})
        return 404, "{}"

    monkeypatch.setattr("emergent_kali.runner_runtime.lab_exchange", fake)
    spec = {
        "url": "http://vampi:5000/openapi.json",
        "status": 200,
        "body": json.dumps(
            {
                "openapi": "3.0.1",
                "paths": {
                    "/users/v1/login": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {"properties": {"username": {}, "password": {}}}
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/register": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {"username": {}, "password": {}, "email": {}}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "/users/v1/{username}/email": {
                        "put": {
                            "requestBody": {
                                "content": {"application/json": {"schema": {"properties": {"email": {}}}}}
                            }
                        }
                    },
                    "/users/v1/{username}": {"get": {}},
                    "/books/v1/{book_title}": {"get": {}},
                },
            }
        ),
    }
    debug = {
        "url": "http://vampi:5000/users/v1/_debug",
        "status": 200,
        "body": '{"users":[{"username":"name1","password":"pw-one"}]}',
    }
    paths = (tmp_path / "spec.json", tmp_path / "session.json", tmp_path / "owners.json")
    session_follow([spec], *paths)
    extra = session_follow([debug], *paths)
    hits = [item for item in extra if (item.get("headers") or {}).get("X-Emerg-Mail") == "1"]
    assert len(hits) == 1
    assert hits[0]["url"].endswith("/users/v1/" + hits[0]["url"].rsplit("/", 1)[-1])
    assert "/books/" not in hits[0]["url"]
    found = detect(hits[0])
    assert [item["title"] for item in found] == ["Another account can change this email"]
    assert found[0]["quote"].endswith("@example.com")
    assert found[0]["quote"] in hits[0]["body"]
    assert found[0]["reproduction"][0].startswith("PUT /users/v1/")
    assert found[0]["reproduction"][0].endswith("/email")


def test_login_errors_quote_the_known_account_response(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    found = detect(
        {
            "url": "http://vampi:5000/users/v1/login",
            "status": 401,
            "headers": {"X-Emerg-Enum": "1"},
            "body": '{"message":"Password is [REDACTED] correct for the given username.","status":"fail"}',
        }
    )
    assert [item["title"] for item in found] == ["Login errors identify a valid account"]
    assert found[0]["quote"] == "correct for the given username."


def test_a_yaml_spec_example_is_not_a_data_leak(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "openapi: 3.0.0\npaths:\n  /users:\n    get:\n      example: ada@example.com\n"
    found = detect({"url": "http://vampi:5000/openapi.yaml", "status": 200, "headers": {}, "body": body})
    assert all(item["title"] != "Public response lists an email address" for item in found)


def test_a_public_product_version_is_quoted_once(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "/*! Example.UI 1.2.3 | license */"
    found = detect(
        {"url": "http://vampi:5000/assets/app.css", "status": 200, "headers": {}, "body": body}
    )
    products = [item for item in found if item["title"] == "Public response shows a product version"]
    assert products[0]["quote"] == "Example.UI 1.2.3"
    spec = '{"openapi":"3.0.0","paths":{"/x":{}}, "note":"Example.UI 1.2.3"}'
    spec_found = detect(
        {"url": "http://vampi:5000/openapi.json", "status": 200, "headers": {}, "body": spec}
    )
    assert all(item["title"] != "Public response shows a product version" for item in spec_found)


def test_a_versioned_server_header_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    found = detect(
        {
            "url": "http://vampi:5000/",
            "status": 200,
            "headers": {"Server": "Example/1.2.3"},
            "body": "ok",
        }
    )
    banners = [item for item in found if item["title"] == "Response header shows a server version"]
    assert banners[0]["quote"] == "Example/1.2.3"


def test_a_server_header_without_a_version_is_ignored(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    found = detect(
        {
            "url": "http://vampi:5000/",
            "status": 200,
            "headers": {"Server": "cloud"},
            "body": "ok",
        }
    )
    assert all(item["title"] != "Response header shows a server version" for item in found)


def test_a_public_download_quotes_the_header(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    header = 'attachment; filename="notes.txt"'
    found = detect(
        {
            "url": "http://vampi:5000/files/notes.txt",
            "status": 200,
            "headers": {"Content-Disposition": header},
            "body": "notes",
        }
    )
    downloads = [item for item in found if item["title"] == "Public response offers a file download"]
    assert downloads[0]["quote"] == "attachment; filename="
    assert "notes.txt" not in downloads[0]["quote"]
    static = detect(
        {
            "url": "http://vampi:5000/ui/app.css",
            "status": 200,
            "headers": {"Content-Disposition": header},
            "body": ".library{}",
        }
    )
    assert all(item["title"] != "Public response offers a file download" for item in static)


def test_a_robots_disallow_line_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    found = detect(
        {
            "url": "http://vampi:5000/robots.txt",
            "status": 200,
            "body": "User-agent: *\nDisallow: /private\n",
        }
    )
    robots = [item for item in found if item["title"] == "Robots file names a private path"]
    assert robots[0]["quote"] == "Disallow: /private"
    missing = detect(
        {
            "url": "http://vampi:5000/robots.txt",
            "status": 404,
            "body": '{"detail":"Disallow: /ftp"}',
        }
    )
    assert all(item["title"] != "Robots file names a private path" for item in missing)


def test_a_security_txt_contact_line_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    found = detect(
        {
            "url": "http://vampi:5000/.well-known/security.txt",
            "status": 200,
            "body": "Contact: mailto:security@example.com\n",
        }
    )
    contacts = [item for item in found if item["title"] == "Security Policy"]
    assert contacts[0]["quote"] == "Contact: mailto:security@example.com"
    missing = detect(
        {
            "url": "http://vampi:5000/.well-known/security.txt",
            "status": 404,
            "body": "Contact: mailto:security@example.com\n",
        }
    )
    assert all(item["title"] != "Security Policy" for item in missing)


def test_an_unauthorized_error_token_is_quoted_on_any_path(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "UnauthorizedError: No Authorization header was found"
    other = detect({"url": "http://vampi:5000/private", "status": 401, "body": body})
    assert len(other) == 1
    assert other[0]["title"] == "Authentication errors expose exception names"
    assert other[0]["quote"] == "UnauthorizedError"
    assert other[0]["quote"] in body
    problem = '{"title":"Unauthorized","status":401,"detail":"Not authorized"}'
    denied = detect({"url": "http://vampi:5000/books/v1/bookTitle5", "status": 401, "body": problem})
    assert all(item["title"] != "Authentication errors expose exception names" for item in denied)
    page = detect(
        {"url": "http://vampi:5000/login", "status": 403, "body": "<html>UnauthorizedError</html>"}
    )
    assert page == []


def test_a_private_file_href_is_quoted_from_any_directory(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = '<a href="notes.bak">notes</a><a href="db.kdbx">db</a>'
    found = detect({"url": "http://vampi:5000/files", "status": 200, "body": body})
    listed = [item for item in found if item["title"] == "Public directory lists a private file"]
    assert len(listed) == 1
    assert listed[0]["quote"] == 'href="notes.bak"'
    assert listed[0]["quote"] in body
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": body})
    assert all(item["title"] != "Public directory lists a private file" for item in script)
    page = "<html><a href=\"/ui/swagger-ui.css\">css</a></html>"
    ui = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    assert all(item["title"] != "Public directory lists a private file" for item in ui)
    src_body = '<img src="backup.zip">'
    src_found = detect({"url": "http://vampi:5000/files", "status": 200, "body": src_body})
    src_listed = [item for item in src_found if item["title"] == "Public directory lists a private file"]
    assert len(src_listed) == 1
    assert src_listed[0]["quote"] == 'src="backup.zip"'
    assert src_listed[0]["quote"] in src_body
    css = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": '<img src="/ui/app.css">'})
    assert all(item["title"] != "Public directory lists a private file" for item in css)


def test_a_password_attribute_is_quoted_from_any_page(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = '<form><input type="password" name="secret"></form>'
    found = detect({"url": "http://vampi:5000/login", "status": 200, "body": body})
    forms = [item for item in found if item["title"] == "Public page contains a password form"]
    assert len(forms) == 1
    assert forms[0]["quote"] == 'type="password"'
    assert forms[0]["quote"] in body
    single = detect({"url": "http://vampi:5000/login", "status": 200, "body": "<input type='password'>"})
    assert [item["quote"] for item in single if item["title"] == "Public page contains a password form"] == [
        "type='password'"
    ]
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": body})
    assert all(item["title"] != "Public page contains a password form" for item in script)
    page = '<html><a href="/ui/swagger-ui.css">css</a></html>'
    ui = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    assert all(item["title"] != "Public page contains a password form" for item in ui)


def test_a_confidential_sentence_is_quoted_on_any_path(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "This document is confidential!\n"
    found = detect({"url": "http://vampi:5000/notes", "status": 200, "body": body})
    notes = [item for item in found if item["title"] == "Confidential Document"]
    assert len(notes) == 1
    assert notes[0]["quote"] == "This document is confidential!"
    assert notes[0]["quote"] in body
    same = detect({"url": "http://vampi:5000/ftp/acquisitions.md", "status": 200, "body": body})
    assert len([item for item in same if item["title"] == "Confidential Document"]) == 1
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": body})
    assert all(item["title"] != "Confidential Document" for item in script)
    missing = detect({"url": "http://vampi:5000/notes", "status": 404, "body": body})
    assert all(item["title"] != "Confidential Document" for item in missing)


def test_a_metrics_help_line_is_quoted_on_any_path(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    line = "# HELP requests_total Total requests"
    body = line + "\n# TYPE requests_total counter\n"
    found = detect({"url": "http://vampi:5000/stats", "status": 200, "body": body})
    metrics = [item for item in found if item["title"] == "Exposed Metrics"]
    assert len(metrics) == 1
    assert metrics[0]["quote"] == line
    assert metrics[0]["quote"] in body
    same = detect(
        {
            "url": "http://vampi:5000/metrics",
            "status": 200,
            "body": "# HELP file_uploads_count uploads\n",
        }
    )
    assert len([item for item in same if item["title"] == "Exposed Metrics"]) == 1
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": body})
    assert all(item["title"] != "Exposed Metrics" for item in script)
    missing = detect({"url": "http://vampi:5000/stats", "status": 404, "body": body})
    assert all(item["title"] != "Exposed Metrics" for item in missing)


def test_a_blocked_file_sentence_is_quoted_on_any_path(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "Only .md and .pdf files are allowed!\n"
    found = detect({"url": "http://vampi:5000/files/notes.bak", "status": 403, "body": body})
    blocked = [item for item in found if item["title"] == "Blocked file name returns a detailed error"]
    assert len(blocked) == 1
    assert blocked[0]["quote"] == "Only .md and .pdf files are allowed!"
    assert blocked[0]["quote"] in body
    same = detect({"url": "http://vampi:5000/ftp/package.json.bak", "status": 403, "body": body})
    assert len([item for item in same if item["quote"] == body.strip()]) == 1
    sales = detect({"url": "http://vampi:5000/ftp/coupons_2013.md.bak", "status": 403, "body": body})
    assert len([item for item in sales if item["quote"] == body.strip()]) == 1
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 403, "body": body})
    assert all(item["title"] != "Blocked file name returns a detailed error" for item in script)
    missing = detect({"url": "http://vampi:5000/files/notes.bak", "status": 200, "body": body})
    assert all(item["title"] != "Blocked file name returns a detailed error" for item in missing)


def test_a_public_key_header_is_quoted_on_any_path(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"
    found = detect({"url": "http://vampi:5000/keys/app.pub", "status": 200, "body": body})
    keys = [item for item in found if item["title"] == "JWT verification key is public"]
    assert len(keys) == 1
    assert keys[0]["quote"] == "-----BEGIN PUBLIC KEY-----"
    assert keys[0]["quote"] in body
    same = detect(
        {
            "url": "http://vampi:5000/encryptionkeys/jwt.pub",
            "status": 200,
            "body": "-----BEGIN RSA PUBLIC KEY-----\nMIIB\n",
        }
    )
    assert len([item for item in same if item["title"] == "JWT verification key is public"]) == 1
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": body})
    assert all(item["title"] != "JWT verification key is public" for item in script)
    missing = detect({"url": "http://vampi:5000/keys/app.pub", "status": 404, "body": body})
    assert all(item["title"] != "JWT verification key is public" for item in missing)
    word = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "BEGIN PUBLIC KEY"})
    assert all(item["title"] != "JWT verification key is public" for item in word)


def test_an_unexpected_path_error_is_quoted_on_any_path(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "Error: Unexpected path\n"
    found = detect({"url": "http://vampi:5000/missing", "status": 500, "body": body})
    errors = [item for item in found if item["title"] == "Error Handling"]
    assert len(errors) == 1
    assert errors[0]["quote"] == "Error: Unexpected path"
    assert errors[0]["quote"] in body
    same = detect({"url": "http://vampi:5000/rest/qwertz", "status": 500, "body": body})
    assert len([item for item in same if item["title"] == "Error Handling"]) == 1
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 500, "body": body})
    assert all(item["title"] != "Error Handling" for item in script)
    missing = detect({"url": "http://vampi:5000/missing", "status": 404, "body": body})
    assert all(item["title"] != "Error Handling" for item in missing)


def test_a_wildcard_origin_header_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/users/v1",
        "status": 200,
        "headers": {"Access-Control-Allow-Origin": "*"},
        "body": '{"users":[]}',
    }
    found = detect(record)
    origins = [item for item in found if item["title"] == "Public response allows any origin"]
    assert len(origins) == 1
    assert origins[0]["quote"] in json.dumps(record)
    assert "*" in origins[0]["quote"]
    assert len(origins[0]["quote"]) >= 8
    named = detect(
        {
            "url": "http://vampi:5000/users/v1",
            "status": 200,
            "headers": {"Access-Control-Allow-Origin": "https://example.com"},
            "body": "{}",
        }
    )
    assert all(item["title"] != "Public response allows any origin" for item in named)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.css",
            "status": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": "body{}",
        }
    )
    assert all(item["title"] != "Public response allows any origin" for item in style)
    page = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Public response allows any origin" for item in page)


def test_a_login_challenge_header_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/users/v1",
        "status": 401,
        "headers": {"WWW-Authenticate": "Bearer realm=api"},
        "body": '{"detail":"missing"}',
    }
    found = detect(record)
    schemes = [item for item in found if item["title"] == "Login challenge names an authentication scheme"]
    assert len(schemes) == 1
    assert schemes[0]["quote"] == "Bearer realm=api"
    assert schemes[0]["quote"] in json.dumps(record)
    short = detect(
        {
            "url": "http://vampi:5000/users/v1",
            "status": 401,
            "headers": {"WWW-Authenticate": "Basic"},
            "body": "{}",
        }
    )
    assert all(item["title"] != "Login challenge names an authentication scheme" for item in short)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.css",
            "status": 401,
            "headers": {"WWW-Authenticate": "Bearer realm=api"},
            "body": "body{}",
        }
    )
    assert all(item["title"] != "Login challenge names an authentication scheme" for item in style)
    page = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 401,
            "headers": {"WWW-Authenticate": "Bearer realm=api"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Login challenge names an authentication scheme" for item in page)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "headers": {"WWW-Authenticate": "Bearer realm=api"},
            "body": '{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Login challenge names an authentication scheme" for item in spec)


def test_a_directory_listing_title_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><h1>Index of /backup</h1></html>"
    found = detect({"url": "http://vampi:5000/files", "status": 200, "body": page})
    listings = [item for item in found if item["title"] == "Public directory lists files"]
    assert len(listings) == 1
    assert listings[0]["quote"] == "Index of /backup"
    assert listings[0]["quote"] in page
    line = detect({"url": "http://vampi:5000/files", "status": 200, "body": "Index of /ftp\nfile.txt"})
    assert [item["quote"] for item in line if item["title"] == "Public directory lists files"] == [
        "Index of /ftp"
    ]
    prose = detect(
        {"url": "http://vampi:5000/files", "status": 200, "body": "See the Index of /docs later."}
    )
    assert all(item["title"] != "Public directory lists files" for item in prose)
    script = detect(
        {"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "<h1>Index of /backup</h1>"}
    )
    assert all(item["title"] != "Public directory lists files" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":">Index of /backup"}',
        }
    )
    assert all(item["title"] != "Public directory lists files" for item in spec)
    missing = detect(
        {"url": "http://vampi:5000/files", "status": 404, "body": "<h1>Index of /backup</h1>"}
    )
    assert all(item["title"] != "Public directory lists files" for item in missing)


def test_a_php_info_page_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><title>phpinfo()</title></html>"
    found = detect({"url": "http://vampi:5000/info", "status": 200, "body": page})
    pages = [item for item in found if item["title"] == "Public response shows a PHP info page"]
    assert len(pages) == 1
    assert pages[0]["quote"] == "phpinfo()"
    assert pages[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/info", "status": 200, "body": "<p>no info</p>"})
    assert all(item["title"] != "Public response shows a PHP info page" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "phpinfo()"})
    assert all(item["title"] != "Public response shows a PHP info page" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"phpinfo()"}',
        }
    )
    assert all(item["title"] != "Public response shows a PHP info page" for item in spec)
    missing = detect({"url": "http://vampi:5000/info", "status": 404, "body": "<html>phpinfo()</html>"})
    assert all(item["title"] != "Public response shows a PHP info page" for item in missing)


def test_a_git_reference_line_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "ref: refs/heads/main\n"
    found = detect({"url": "http://vampi:5000/meta", "status": 200, "body": body})
    refs = [item for item in found if item["title"] == "Public response exposes a git reference"]
    assert len(refs) == 1
    assert refs[0]["quote"] == "ref: refs/heads/main"
    assert refs[0]["quote"] in body
    page = detect(
        {"url": "http://vampi:5000/meta", "status": 200, "body": "<pre>\nref: refs/heads/dev\n</pre>"}
    )
    assert [item["quote"] for item in page if item["title"] == "Public response exposes a git reference"] == [
        "ref: refs/heads/dev"
    ]
    prose = detect(
        {"url": "http://vampi:5000/meta", "status": 200, "body": "See ref: refs/heads/main later."}
    )
    assert all(item["title"] != "Public response exposes a git reference" for item in prose)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "ref: refs/heads/main\n"})
    assert all(item["title"] != "Public response exposes a git reference" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": 'ref: refs/heads/main\n{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Public response exposes a git reference" for item in spec)
    missing = detect({"url": "http://vampi:5000/meta", "status": 404, "body": "ref: refs/heads/main\n"})
    assert all(item["title"] != "Public response exposes a git reference" for item in missing)


def test_a_framework_error_page_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "<html><h1>Whitelabel Error Page</h1></html>"
    found = detect({"url": "http://vampi:5000/missing", "status": 404, "body": body})
    pages = [item for item in found if item["title"] == "Public response shows a framework error page"]
    assert len(pages) == 1
    assert pages[0]["quote"] == "Whitelabel Error Page"
    assert pages[0]["quote"] in body
    failed = detect({"url": "http://vampi:5000/missing", "status": 500, "body": body})
    assert len([item for item in failed if item["title"] == "Public response shows a framework error page"]) == 1
    plain = detect({"url": "http://vampi:5000/missing", "status": 404, "body": "<html>missing</html>"})
    assert all(item["title"] != "Public response shows a framework error page" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 500, "body": "Whitelabel Error Page"})
    assert all(item["title"] != "Public response shows a framework error page" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 500,
            "body": '{"openapi":"3.0.0","paths":{},"note":"Whitelabel Error Page"}',
        }
    )
    assert all(item["title"] != "Public response shows a framework error page" for item in spec)


def test_a_private_key_header_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n"
    found = detect({"url": "http://vampi:5000/meta", "status": 200, "body": body})
    keys = [item for item in found if item["title"] == "Public response exposes a private key"]
    assert len(keys) == 1
    assert keys[0]["quote"] == "-----BEGIN RSA PRIVATE KEY-----"
    assert keys[0]["quote"] in body
    assert all(item["title"] != "JWT verification key is public" for item in found)
    both = "-----BEGIN PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----\n"
    longer = detect({"url": "http://vampi:5000/meta", "status": 404, "body": both})
    assert [item["quote"] for item in longer if item["title"] == "Public response exposes a private key"] == [
        "-----BEGIN RSA PRIVATE KEY-----"
    ]
    public = detect(
        {"url": "http://vampi:5000/meta", "status": 200, "body": "-----BEGIN PUBLIC KEY-----\nMIIB\n"}
    )
    assert all(item["title"] != "Public response exposes a private key" for item in public)
    assert any(item["title"] == "JWT verification key is public" for item in public)
    script = detect(
        {"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "-----BEGIN RSA PRIVATE KEY-----\n"}
    )
    assert all(item["title"] != "Public response exposes a private key" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"-----BEGIN RSA PRIVATE KEY-----"}',
        }
    )
    assert all(item["title"] != "Public response exposes a private key" for item in spec)


def test_a_cookie_without_httponly_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/users/v1",
        "status": 200,
        "headers": {"Set-Cookie": "session=abc12345; Path=/"},
        "body": '{"users":[]}',
    }
    found = detect(record)
    cookies = [item for item in found if item["title"] == "Public response sets a cookie without HttpOnly"]
    assert len(cookies) == 1
    assert cookies[0]["quote"] == "session=abc12345; Path=/"
    assert cookies[0]["quote"] in json.dumps(record)
    locked = detect(
        {
            "url": "http://vampi:5000/users/v1",
            "status": 200,
            "headers": {"Set-Cookie": "session=abc12345; HttpOnly"},
            "body": "{}",
        }
    )
    assert all(item["title"] != "Public response sets a cookie without HttpOnly" for item in locked)
    short = detect(
        {
            "url": "http://vampi:5000/users/v1",
            "status": 200,
            "headers": {"Set-Cookie": "a=b"},
            "body": "{}",
        }
    )
    assert all(item["title"] != "Public response sets a cookie without HttpOnly" for item in short)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.css",
            "status": 200,
            "headers": {"Set-Cookie": "session=abc12345; Path=/"},
            "body": "body{}",
        }
    )
    assert all(item["title"] != "Public response sets a cookie without HttpOnly" for item in style)
    page = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {"Set-Cookie": "session=abc12345; Path=/"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Public response sets a cookie without HttpOnly" for item in page)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "headers": {"Set-Cookie": "session=abc12345; Path=/"},
            "body": '{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Public response sets a cookie without HttpOnly" for item in spec)


def test_a_debug_true_line_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    spaced = detect({"url": "http://vampi:5000/settings", "status": 200, "body": "DEBUG = True\n"})
    flags = [item for item in spaced if item["title"] == "Public response shows a debug flag"]
    assert len(flags) == 1
    assert flags[0]["quote"] == "DEBUG = True"
    tight = detect({"url": "http://vampi:5000/settings", "status": 200, "body": "DEBUG=True\n"})
    assert [item["quote"] for item in tight if item["title"] == "Public response shows a debug flag"] == [
        "DEBUG=True"
    ]
    off = detect({"url": "http://vampi:5000/settings", "status": 200, "body": "DEBUG = False\n"})
    assert all(item["title"] != "Public response shows a debug flag" for item in off)
    prose = detect({"url": "http://vampi:5000/settings", "status": 200, "body": "see DEBUG = True later"})
    assert all(item["title"] != "Public response shows a debug flag" for item in prose)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "DEBUG = True\n"})
    assert all(item["title"] != "Public response shows a debug flag" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": 'DEBUG = True\n{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Public response shows a debug flag" for item in spec)


def test_an_inline_script_policy_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/ui/",
        "status": 200,
        "headers": {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
        "body": "<html></html>",
    }
    found = detect(record)
    policies = [item for item in found if item["title"] == "Public response allows inline scripts"]
    assert len(policies) == 1
    assert policies[0]["quote"] == "unsafe-inline"
    assert policies[0]["quote"] in json.dumps(record)
    body_only = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {},
            "body": "<html>unsafe-inline</html>",
        }
    )
    assert all(item["title"] != "Public response allows inline scripts" for item in body_only)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.css",
            "status": 200,
            "headers": {"Content-Security-Policy": "default-src 'unsafe-inline'"},
            "body": "body{}",
        }
    )
    assert all(item["title"] != "Public response allows inline scripts" for item in style)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "headers": {"Content-Security-Policy": "default-src 'unsafe-inline'"},
            "body": '{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Public response allows inline scripts" for item in spec)


def test_a_dynamic_code_policy_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/ui/",
        "status": 200,
        "headers": {"Content-Security-Policy": "script-src 'unsafe-inline' 'unsafe-eval'"},
        "body": "<html></html>",
    }
    found = detect(record)
    dynamic = [item for item in found if item["title"] == "Public response allows dynamic code"]
    assert len(dynamic) == 1
    assert dynamic[0]["quote"] == "unsafe-eval"
    assert dynamic[0]["quote"] in json.dumps(record)
    assert any(item["title"] == "Public response allows inline scripts" for item in found)
    body_only = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {},
            "body": "<html>unsafe-eval</html>",
        }
    )
    assert all(item["title"] != "Public response allows dynamic code" for item in body_only)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.css",
            "status": 200,
            "headers": {"Content-Security-Policy": "script-src 'unsafe-eval'"},
            "body": "body{}",
        }
    )
    assert all(item["title"] != "Public response allows dynamic code" for item in style)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "headers": {"Content-Security-Policy": "script-src 'unsafe-eval'"},
            "body": '{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Public response allows dynamic code" for item in spec)


def test_an_encoded_token_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    token = "eyJhbGciOiJIUzI1NiJ9"
    body = '{"access":"' + token + '"}'
    found = detect({"url": "http://vampi:5000/users/v1", "status": 200, "body": body})
    tokens = [item for item in found if item["title"] == "Public response includes an encoded token"]
    assert len(tokens) == 1
    assert tokens[0]["quote"] == token
    assert tokens[0]["quote"] in body
    assert len(tokens[0]["quote"]) <= 80
    short = detect({"url": "http://vampi:5000/users/v1", "status": 200, "body": '{"access":"eyJshort"}'})
    assert all(item["title"] != "Public response includes an encoded token" for item in short)
    page = detect(
        {"url": "http://vampi:5000/ui/", "status": 200, "body": "<html>" + token + "</html>"}
    )
    assert all(item["title"] != "Public response includes an encoded token" for item in page)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": token})
    assert all(item["title"] != "Public response includes an encoded token" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"' + token + '"}',
        }
    )
    assert all(item["title"] != "Public response includes an encoded token" for item in spec)
    missing = detect({"url": "http://vampi:5000/users/v1", "status": 404, "body": body})
    assert all(item["title"] != "Public response includes an encoded token" for item in missing)


def test_a_framing_header_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/ui/",
        "status": 200,
        "headers": {"X-Frame-Options": "ALLOW-FROM https://example.com"},
        "body": "<html></html>",
    }
    found = detect(record)
    frames = [item for item in found if item["title"] == "Public response allows framing"]
    assert len(frames) == 1
    assert frames[0]["quote"] == "ALLOW-FROM https://example.com"
    assert frames[0]["quote"] in json.dumps(record)
    same = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {"X-Frame-Options": "SAMEORIGIN"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Public response allows framing" for item in same)
    deny = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {"X-Frame-Options": "DENY"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Public response allows framing" for item in deny)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.css",
            "status": 200,
            "headers": {"X-Frame-Options": "ALLOW-FROM https://example.com"},
            "body": "body{}",
        }
    )
    assert all(item["title"] != "Public response allows framing" for item in style)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "headers": {"X-Frame-Options": "ALLOW-FROM https://example.com"},
            "body": '{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Public response allows framing" for item in spec)


def test_json_labeled_as_html_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/data",
        "status": 200,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": '{"ok":1}',
    }
    found = detect(record)
    labels = [item for item in found if item["title"] == "Public response labels JSON as HTML"]
    assert len(labels) == 1
    assert labels[0]["quote"] == "text/html; charset=utf-8"
    assert labels[0]["quote"] in json.dumps(record)
    page = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {"Content-Type": "text/html; charset=utf-8"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Public response labels JSON as HTML" for item in page)
    real = detect(
        {
            "url": "http://vampi:5000/data",
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"ok":1}',
        }
    )
    assert all(item["title"] != "Public response labels JSON as HTML" for item in real)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.js",
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": '{"ok":1}',
        }
    )
    assert all(item["title"] != "Public response labels JSON as HTML" for item in style)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": '{"openapi":"3.0.0","paths":{}}',
        }
    )
    assert all(item["title"] != "Public response labels JSON as HTML" for item in spec)


def test_html_labeled_as_json_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    record = {
        "url": "http://vampi:5000/ui/",
        "status": 200,
        "headers": {"Content-Type": "application/json"},
        "body": "<html></html>",
    }
    found = detect(record)
    labels = [item for item in found if item["title"] == "Public response labels HTML as JSON"]
    assert len(labels) == 1
    assert labels[0]["quote"] == "application/json"
    assert labels[0]["quote"] in json.dumps(record)
    data = detect(
        {
            "url": "http://vampi:5000/data",
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"ok":1}',
        }
    )
    assert all(item["title"] != "Public response labels HTML as JSON" for item in data)
    page = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Public response labels HTML as JSON" for item in page)
    style = detect(
        {
            "url": "http://vampi:5000/ui/app.js",
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": "<html></html>",
        }
    )
    assert all(item["title"] != "Public response labels HTML as JSON" for item in style)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '<html>{"openapi":"3.0.0","paths":{}}</html>',
        }
    )
    assert all(item["title"] != "Public response labels HTML as JSON" for item in spec)


def test_a_meta_refresh_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = '<html><meta http-equiv="refresh" content="0;url=/next"></html>'
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    refreshes = [item for item in found if item["title"] == "Public page refreshes to another address"]
    assert len(refreshes) == 1
    assert refreshes[0]["quote"] == 'http-equiv="refresh"'
    assert refreshes[0]["quote"] in page
    single = detect(
        {"url": "http://vampi:5000/ui/", "status": 200, "body": "<meta http-equiv='refresh'>"}
    )
    assert [item["quote"] for item in single if item["title"] == "Public page refreshes to another address"] == [
        "http-equiv='refresh'"
    ]
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page refreshes to another address" for item in plain)
    script = detect(
        {"url": "http://vampi:5000/ui/app.js", "status": 200, "body": '<meta http-equiv="refresh">'}
    )
    assert all(item["title"] != "Public page refreshes to another address" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"http-equiv=\\"refresh\\""}',
        }
    )
    assert all(item["title"] != "Public page refreshes to another address" for item in spec)
    missing = detect(
        {"url": "http://vampi:5000/ui/", "status": 404, "body": '<meta http-equiv="refresh">'}
    )
    assert all(item["title"] != "Public page refreshes to another address" for item in missing)


def test_a_cookie_script_read_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>var value = document.cookie;</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    reads = [item for item in found if item["title"] == "Public page reads a cookie from script"]
    assert len(reads) == 1
    assert reads[0]["quote"] == "document.cookie"
    assert reads[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page reads a cookie from script" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "document.cookie"})
    assert all(item["title"] != "Public page reads a cookie from script" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"document.cookie"}',
        }
    )
    assert all(item["title"] != "Public page reads a cookie from script" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page reads a cookie from script" for item in missing)


def test_a_markup_write_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>node.innerHTML = name;</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    writes = [item for item in found if item["title"] == "Public page writes markup from script"]
    assert len(writes) == 1
    assert writes[0]["quote"] == "innerHTML"
    assert writes[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page writes markup from script" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "node.innerHTML = name;"})
    assert all(item["title"] != "Public page writes markup from script" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"innerHTML"}',
        }
    )
    assert all(item["title"] != "Public page writes markup from script" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page writes markup from script" for item in missing)


def test_a_document_write_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>document.write(name);</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    writes = [item for item in found if item["title"] == "Public page writes the document from script"]
    assert len(writes) == 1
    assert writes[0]["quote"] == "document.write"
    assert writes[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page writes the document from script" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "document.write(name);"})
    assert all(item["title"] != "Public page writes the document from script" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"document.write"}',
        }
    )
    assert all(item["title"] != "Public page writes the document from script" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page writes the document from script" for item in missing)


def test_local_storage_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>var value = localStorage.getItem('name');</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    reads = [item for item in found if item["title"] == "Public page reads local storage"]
    assert len(reads) == 1
    assert reads[0]["quote"] == "localStorage"
    assert reads[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page reads local storage" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "localStorage.getItem('name')"})
    assert all(item["title"] != "Public page reads local storage" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"localStorage"}',
        }
    )
    assert all(item["title"] != "Public page reads local storage" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page reads local storage" for item in missing)


def test_session_storage_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>var value = sessionStorage.getItem('name');</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    reads = [item for item in found if item["title"] == "Public page reads session storage"]
    assert len(reads) == 1
    assert reads[0]["quote"] == "sessionStorage"
    assert reads[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page reads session storage" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "sessionStorage.getItem('name')"})
    assert all(item["title"] != "Public page reads session storage" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"sessionStorage"}',
        }
    )
    assert all(item["title"] != "Public page reads session storage" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page reads session storage" for item in missing)


def test_browser_database_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>var store = indexedDB.open('notes');</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    reads = [item for item in found if item["title"] == "Public page reads a browser database"]
    assert len(reads) == 1
    assert reads[0]["quote"] == "indexedDB"
    assert reads[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page reads a browser database" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "indexedDB.open('notes')"})
    assert all(item["title"] != "Public page reads a browser database" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"indexedDB"}',
        }
    )
    assert all(item["title"] != "Public page reads a browser database" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page reads a browser database" for item in missing)


def test_browser_message_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>parent.postMessage('ready', '*');</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    sends = [item for item in found if item["title"] == "Public page sends a browser message"]
    assert len(sends) == 1
    assert sends[0]["quote"] == "postMessage"
    assert sends[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page sends a browser message" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "parent.postMessage('ready', '*')"})
    assert all(item["title"] != "Public page sends a browser message" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"postMessage"}',
        }
    )
    assert all(item["title"] != "Public page sends a browser message" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page sends a browser message" for item in missing)


def test_page_socket_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>var link = new WebSocket('ws://lab/live');</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    opens = [item for item in found if item["title"] == "Public page opens a socket"]
    assert len(opens) == 1
    assert opens[0]["quote"] == "WebSocket"
    assert opens[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page opens a socket" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "new WebSocket('ws://lab/live')"})
    assert all(item["title"] != "Public page opens a socket" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"WebSocket"}',
        }
    )
    assert all(item["title"] != "Public page opens a socket" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page opens a socket" for item in missing)


def test_document_domain_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>document.domain = 'lab.local';</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    sets = [item for item in found if item["title"] == "Public page sets the document domain"]
    assert len(sets) == 1
    assert sets[0]["quote"] == "document.domain"
    assert sets[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page sets the document domain" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "document.domain = 'lab.local'"})
    assert all(item["title"] != "Public page sets the document domain" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"document.domain"}',
        }
    )
    assert all(item["title"] != "Public page sets the document domain" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page sets the document domain" for item in missing)


def test_window_open_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>window.open('/next');</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    opens = [item for item in found if item["title"] == "Public page opens another window"]
    assert len(opens) == 1
    assert opens[0]["quote"] == "window.open"
    assert opens[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page opens another window" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "window.open('/next')"})
    assert all(item["title"] != "Public page opens another window" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"window.open"}',
        }
    )
    assert all(item["title"] != "Public page opens another window" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page opens another window" for item in missing)


def test_browser_request_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>var call = new XMLHttpRequest();</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    sends = [item for item in found if item["title"] == "Public page sends a browser request"]
    assert len(sends) == 1
    assert sends[0]["quote"] == "XMLHttpRequest"
    assert sends[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page sends a browser request" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "new XMLHttpRequest()"})
    assert all(item["title"] != "Public page sends a browser request" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"XMLHttpRequest"}',
        }
    )
    assert all(item["title"] != "Public page sends a browser request" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page sends a browser request" for item in missing)


def test_browser_address_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>location.href = '/next';</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    sends = [item for item in found if item["title"] == "Public page sends the browser to another address"]
    assert len(sends) == 1
    assert sends[0]["quote"] == "location.href"
    assert sends[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page sends the browser to another address" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "location.href = '/next'"})
    assert all(item["title"] != "Public page sends the browser to another address" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"location.href"}',
        }
    )
    assert all(item["title"] != "Public page sends the browser to another address" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page sends the browser to another address" for item in missing)


def test_outer_markup_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>node.outerHTML = '<b>note</b>';</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    writes = [item for item in found if item["title"] == "Public page writes outer markup from script"]
    assert len(writes) == 1
    assert writes[0]["quote"] == "outerHTML"
    assert writes[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page writes outer markup from script" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "node.outerHTML = '<b>note</b>'"})
    assert all(item["title"] != "Public page writes outer markup from script" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"outerHTML"}',
        }
    )
    assert all(item["title"] != "Public page writes outer markup from script" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page writes outer markup from script" for item in missing)


def test_worker_script_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><script>importScripts('/worker.js');</script></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    loads = [item for item in found if item["title"] == "Public page loads a worker script"]
    assert len(loads) == 1
    assert loads[0]["quote"] == "importScripts"
    assert loads[0]["quote"] in page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public page loads a worker script" for item in plain)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "importScripts('/worker.js')"})
    assert all(item["title"] != "Public page loads a worker script" for item in script)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"importScripts"}',
        }
    )
    assert all(item["title"] != "Public page loads a worker script" for item in spec)
    missing = detect({"url": "http://vampi:5000/ui/", "status": 404, "body": page})
    assert all(item["title"] != "Public page loads a worker script" for item in missing)


def test_database_address_quotes_the_scheme_only(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html>mongodb://app:hidden@db/app</html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response includes a database address"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "mongodb://"
    assert hits[0]["quote"] in page
    assert "hidden" not in hits[0]["quote"]
    both = "<html>mysql://a@db postgres://b@db</html>"
    longer = detect({"url": "http://vampi:5000/ui/", "status": 500, "body": both})
    chosen = [item for item in longer if item["title"] == "Public response includes a database address"]
    assert len(chosen) == 1
    assert chosen[0]["quote"] == "postgres://"
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "redis://cache/0"})
    static_hits = [item for item in script if item["title"] == "Public response includes a database address"]
    assert len(static_hits) == 1
    assert static_hits[0]["quote"] == "redis://"
    sqlite_page = "<html>mysql://a@db sqlite://file.db</html>"
    sqlite_found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": sqlite_page})
    sqlite_hits = [item for item in sqlite_found if item["title"] == "Public response includes a database address"]
    assert len(sqlite_hits) == 1
    assert sqlite_hits[0]["quote"] == "sqlite://"
    assert sqlite_hits[0]["quote"] in sqlite_page
    mssql_page = "<html>mysql://a@db mssql://b@db</html>"
    mssql_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": mssql_page})
    mssql_hits = [item for item in mssql_found if item["title"] == "Public response includes a database address"]
    assert len(mssql_hits) == 1
    assert mssql_hits[0]["quote"] == "mssql://"
    assert mssql_hits[0]["quote"] in mssql_page
    oracle_page = "<html>mssql://b@db oracle://c@db</html>"
    oracle_found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": oracle_page})
    oracle_hits = [item for item in oracle_found if item["title"] == "Public response includes a database address"]
    assert len(oracle_hits) == 1
    assert oracle_hits[0]["quote"] == "oracle://"
    assert oracle_hits[0]["quote"] in oracle_page
    cassandra_page = "<html>postgres://a@db cassandra://b@db</html>"
    cassandra_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": cassandra_page})
    cassandra_hits = [
        item for item in cassandra_found if item["title"] == "Public response includes a database address"
    ]
    assert len(cassandra_hits) == 1
    assert cassandra_hits[0]["quote"] == "cassandra://"
    assert cassandra_hits[0]["quote"] in cassandra_page
    couch_page = "<html>sqlite://file.db couchdb://a@db</html>"
    couch_found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": couch_page})
    couch_hits = [item for item in couch_found if item["title"] == "Public response includes a database address"]
    assert len(couch_hits) == 1
    assert couch_hits[0]["quote"] == "couchdb://"
    assert couch_hits[0]["quote"] in couch_page
    neo_page = "<html>mssql://b@db neo4j://a@db</html>"
    neo_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": neo_page})
    neo_hits = [item for item in neo_found if item["title"] == "Public response includes a database address"]
    assert len(neo_hits) == 1
    assert neo_hits[0]["quote"] == "neo4j://"
    assert neo_hits[0]["quote"] in neo_page
    pg_page = "<html>postgres://a@db postgresql://b@db</html>"
    pg_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": pg_page})
    pg_hits = [item for item in pg_found if item["title"] == "Public response includes a database address"]
    assert len(pg_hits) == 1
    assert pg_hits[0]["quote"] == "postgresql://"
    assert pg_hits[0]["quote"] in pg_page
    mem_page = "<html>cassandra://a@db memcached://b@db</html>"
    mem_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": mem_page})
    mem_hits = [item for item in mem_found if item["title"] == "Public response includes a database address"]
    assert len(mem_hits) == 1
    assert mem_hits[0]["quote"] == "memcached://"
    assert mem_hits[0]["quote"] in mem_page
    srv_page = "<html>postgresql://a@db mongodb+srv://b@db</html>"
    srv_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": srv_page})
    srv_hits = [item for item in srv_found if item["title"] == "Public response includes a database address"]
    assert len(srv_hits) == 1
    assert srv_hits[0]["quote"] == "mongodb+srv://"
    assert srv_hits[0]["quote"] in srv_page
    es_page = "<html>mongodb+srv://a@db elasticsearch://b@db</html>"
    es_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": es_page})
    es_hits = [item for item in es_found if item["title"] == "Public response includes a database address"]
    assert len(es_hits) == 1
    assert es_hits[0]["quote"] == "elasticsearch://"
    assert es_hits[0]["quote"] in es_page
    jdbc_page = "<html>elasticsearch://a@db jdbc:postgresql://b@db</html>"
    jdbc_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jdbc_page})
    jdbc_hits = [item for item in jdbc_found if item["title"] == "Public response includes a database address"]
    assert len(jdbc_hits) == 1
    assert jdbc_hits[0]["quote"] == "jdbc:postgresql://"
    assert jdbc_hits[0]["quote"] in jdbc_page
    ch_page = "<html>postgresql://a@db clickhouse://b@db</html>"
    ch_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ch_page})
    ch_hits = [item for item in ch_found if item["title"] == "Public response includes a database address"]
    assert len(ch_hits) == 1
    assert ch_hits[0]["quote"] == "clickhouse://"
    assert ch_hits[0]["quote"] in ch_page
    my_page = "<html>mysql://a@db jdbc:mysql://b@db</html>"
    my_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": my_page})
    my_hits = [item for item in my_found if item["title"] == "Public response includes a database address"]
    assert len(my_hits) == 1
    assert my_hits[0]["quote"] == "jdbc:mysql://"
    assert my_hits[0]["quote"] in my_page
    os_page = "<html>postgresql://a@db opensearch://b@db</html>"
    os_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": os_page})
    os_hits = [item for item in os_found if item["title"] == "Public response includes a database address"]
    assert len(os_hits) == 1
    assert os_hits[0]["quote"] == "opensearch://"
    assert os_hits[0]["quote"] in os_page
    cr_page = "<html>postgres://a@db cockroach://b@db</html>"
    cr_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": cr_page})
    cr_hits = [item for item in cr_found if item["title"] == "Public response includes a database address"]
    assert len(cr_hits) == 1
    assert cr_hits[0]["quote"] == "cockroach://"
    assert cr_hits[0]["quote"] in cr_page
    in_page = "<html>postgres://a@db influxdb://b@db</html>"
    in_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": in_page})
    in_hits = [item for item in in_found if item["title"] == "Public response includes a database address"]
    assert len(in_hits) == 1
    assert in_hits[0]["quote"] == "influxdb://"
    assert in_hits[0]["quote"] in in_page
    ts_page = "<html>influxdb://a@db timescale://b@db</html>"
    ts_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ts_page})
    ts_hits = [item for item in ts_found if item["title"] == "Public response includes a database address"]
    assert len(ts_hits) == 1
    assert ts_hits[0]["quote"] == "timescale://"
    assert ts_hits[0]["quote"] in ts_page
    ss_page = "<html>influxdb://a@db sqlserver://b@db</html>"
    ss_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ss_page})
    ss_hits = [item for item in ss_found if item["title"] == "Public response includes a database address"]
    assert len(ss_hits) == 1
    assert ss_hits[0]["quote"] == "sqlserver://"
    assert ss_hits[0]["quote"] in ss_page
    ma_page = "<html>sqlite://a@db mariadb://b@db</html>"
    ma_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ma_page})
    ma_hits = [item for item in ma_found if item["title"] == "Public response includes a database address"]
    assert len(ma_hits) == 1
    assert ma_hits[0]["quote"] == "mariadb://"
    assert ma_hits[0]["quote"] in ma_page
    dy_page = "<html>postgres://a@db dynamodb://b@db</html>"
    dy_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": dy_page})
    dy_hits = [item for item in dy_found if item["title"] == "Public response includes a database address"]
    assert len(dy_hits) == 1
    assert dy_hits[0]["quote"] == "dynamodb://"
    assert dy_hits[0]["quote"] in dy_page
    fs_page = "<html>influxdb://a@db firestore://b@db</html>"
    fs_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": fs_page})
    fs_hits = [item for item in fs_found if item["title"] == "Public response includes a database address"]
    assert len(fs_hits) == 1
    assert fs_hits[0]["quote"] == "firestore://"
    assert fs_hits[0]["quote"] in fs_page
    sf_page = "<html>influxdb://a@db snowflake://b@db</html>"
    sf_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sf_page})
    sf_hits = [item for item in sf_found if item["title"] == "Public response includes a database address"]
    assert len(sf_hits) == 1
    assert sf_hits[0]["quote"] == "snowflake://"
    assert sf_hits[0]["quote"] in sf_page
    co_page = "<html>postgres://a@db cosmosdb://b@db</html>"
    co_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": co_page})
    co_hits = [item for item in co_found if item["title"] == "Public response includes a database address"]
    assert len(co_hits) == 1
    assert co_hits[0]["quote"] == "cosmosdb://"
    assert co_hits[0]["quote"] in co_page
    r2_page = "<html>jdbc:postgresql://a@db r2dbc:postgresql://b@db</html>"
    r2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": r2_page})
    r2_hits = [item for item in r2_found if item["title"] == "Public response includes a database address"]
    assert len(r2_hits) == 1
    assert r2_hits[0]["quote"] == "r2dbc:postgresql://"
    assert r2_hits[0]["quote"] in r2_page
    rm_page = "<html>mysql://a@db r2dbc:mysql://b@db</html>"
    rm_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rm_page})
    rm_hits = [item for item in rm_found if item["title"] == "Public response includes a database address"]
    assert len(rm_hits) == 1
    assert rm_hits[0]["quote"] == "r2dbc:mysql://"
    assert rm_hits[0]["quote"] in rm_page
    rd_page = "<html>mariadb://a@db r2dbc:mariadb://b@db</html>"
    rd_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rd_page})
    rd_hits = [item for item in rd_found if item["title"] == "Public response includes a database address"]
    assert len(rd_hits) == 1
    assert rd_hits[0]["quote"] == "r2dbc:mariadb://"
    assert rd_hits[0]["quote"] in rd_page
    rs_page = "<html>redis://a@db rediss://b@db</html>"
    rs_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rs_page})
    rs_hits = [item for item in rs_found if item["title"] == "Public response includes a database address"]
    assert len(rs_hits) == 1
    assert rs_hits[0]["quote"] == "rediss://"
    assert rs_hits[0]["quote"] in rs_page
    ar_page = "<html>influxdb://a@db arangodb://b@db</html>"
    ar_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ar_page})
    ar_hits = [item for item in ar_found if item["title"] == "Public response includes a database address"]
    assert len(ar_hits) == 1
    assert ar_hits[0]["quote"] == "arangodb://"
    assert ar_hits[0]["quote"] in ar_page
    rt_page = "<html>influxdb://a@db rethinkdb://b@db</html>"
    rt_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rt_page})
    rt_hits = [item for item in rt_found if item["title"] == "Public response includes a database address"]
    assert len(rt_hits) == 1
    assert rt_hits[0]["quote"] == "rethinkdb://"
    assert rt_hits[0]["quote"] in rt_page
    ta_page = "<html>influxdb://a@db tarantool://b@db</html>"
    ta_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ta_page})
    ta_hits = [item for item in ta_found if item["title"] == "Public response includes a database address"]
    assert len(ta_hits) == 1
    assert ta_hits[0]["quote"] == "tarantool://"
    assert ta_hits[0]["quote"] in ta_page
    or_page = "<html>postgres://a@db orientdb://b@db</html>"
    or_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": or_page})
    or_hits = [item for item in or_found if item["title"] == "Public response includes a database address"]
    assert len(or_hits) == 1
    assert or_hits[0]["quote"] == "orientdb://"
    assert or_hits[0]["quote"] in or_page
    yu_page = "<html>postgres://a@db yugabyte://b@db</html>"
    yu_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": yu_page})
    yu_hits = [item for item in yu_found if item["title"] == "Public response includes a database address"]
    assert len(yu_hits) == 1
    assert yu_hits[0]["quote"] == "yugabyte://"
    assert yu_hits[0]["quote"] in yu_page
    sc_page = "<html>postgres://a@db scylladb://b@db</html>"
    sc_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sc_page})
    sc_hits = [item for item in sc_found if item["title"] == "Public response includes a database address"]
    assert len(sc_hits) == 1
    assert sc_hits[0]["quote"] == "scylladb://"
    assert sc_hits[0]["quote"] in sc_page
    vo_page = "<html>neo4j://a@db voltdb://b@db</html>"
    vo_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": vo_page})
    vo_hits = [item for item in vo_found if item["title"] == "Public response includes a database address"]
    assert len(vo_hits) == 1
    assert vo_hits[0]["quote"] == "voltdb://"
    assert vo_hits[0]["quote"] in vo_page
    ig_page = "<html>neo4j://a@db ignite://b@db</html>"
    ig_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ig_page})
    ig_hits = [item for item in ig_found if item["title"] == "Public response includes a database address"]
    assert len(ig_hits) == 1
    assert ig_hits[0]["quote"] == "ignite://"
    assert ig_hits[0]["quote"] in ig_page
    hb_page = "<html>neo4j://a@db hbase://b@db</html>"
    hb_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": hb_page})
    hb_hits = [item for item in hb_found if item["title"] == "Public response includes a database address"]
    assert len(hb_hits) == 1
    assert hb_hits[0]["quote"] == "hbase://"
    assert hb_hits[0]["quote"] in hb_page
    cb_page = "<html>influxdb://a@db couchbase://b@db</html>"
    cb_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": cb_page})
    cb_hits = [item for item in cb_found if item["title"] == "Public response includes a database address"]
    assert len(cb_hits) == 1
    assert cb_hits[0]["quote"] == "couchbase://"
    assert cb_hits[0]["quote"] in cb_page
    fd_page = "<html>r2dbc:mysql://a@db foundationdb://b@db</html>"
    fd_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": fd_page})
    fd_hits = [item for item in fd_found if item["title"] == "Public response includes a database address"]
    assert len(fd_hits) == 1
    assert fd_hits[0]["quote"] == "foundationdb://"
    assert fd_hits[0]["quote"] in fd_page
    bt_page = "<html>postgres://a@db bigtable://b@db</html>"
    bt_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": bt_page})
    bt_hits = [item for item in bt_found if item["title"] == "Public response includes a database address"]
    assert len(bt_hits) == 1
    assert bt_hits[0]["quote"] == "bigtable://"
    assert bt_hits[0]["quote"] in bt_page
    fa_page = "<html>sqlite://a@db faunadb://b@db</html>"
    fa_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": fa_page})
    fa_hits = [item for item in fa_found if item["title"] == "Public response includes a database address"]
    assert len(fa_hits) == 1
    assert fa_hits[0]["quote"] == "faunadb://"
    assert fa_hits[0]["quote"] in fa_page
    sp_page = "<html>sqlite://a@db spanner://b@db</html>"
    sp_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sp_page})
    sp_hits = [item for item in sp_found if item["title"] == "Public response includes a database address"]
    assert len(sp_hits) == 1
    assert sp_hits[0]["quote"] == "spanner://"
    assert sp_hits[0]["quote"] in sp_page
    ix_page = "<html>postgres://a@db informix://b@db</html>"
    ix_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ix_page})
    ix_hits = [item for item in ix_found if item["title"] == "Public response includes a database address"]
    assert len(ix_hits) == 1
    assert ix_hits[0]["quote"] == "informix://"
    assert ix_hits[0]["quote"] in ix_page
    sb_page = "<html>hbase://a@db sybase://b@db</html>"
    sb_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sb_page})
    sb_hits = [item for item in sb_found if item["title"] == "Public response includes a database address"]
    assert len(sb_hits) == 1
    assert sb_hits[0]["quote"] == "sybase://"
    assert sb_hits[0]["quote"] in sb_page
    ex_page = "<html>hbase://a@db exasol://b@db</html>"
    ex_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ex_page})
    ex_hits = [item for item in ex_found if item["title"] == "Public response includes a database address"]
    assert len(ex_hits) == 1
    assert ex_hits[0]["quote"] == "exasol://"
    assert ex_hits[0]["quote"] in ex_page
    cr_page = "<html>neo4j://a@db crate://b@db</html>"
    cr_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": cr_page})
    cr_hits = [item for item in cr_found if item["title"] == "Public response includes a database address"]
    assert len(cr_hits) == 1
    assert cr_hits[0]["quote"] == "crate://"
    assert cr_hits[0]["quote"] in cr_page
    vt_page = "<html>neo4j://a@db vertica://b@db</html>"
    vt_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": vt_page})
    vt_hits = [item for item in vt_found if item["title"] == "Public response includes a database address"]
    assert len(vt_hits) == 1
    assert vt_hits[0]["quote"] == "vertica://"
    assert vt_hits[0]["quote"] in vt_page
    td_page = "<html>neo4j://a@db teradata://b@db</html>"
    td_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": td_page})
    td_hits = [item for item in td_found if item["title"] == "Public response includes a database address"]
    assert len(td_hits) == 1
    assert td_hits[0]["quote"] == "teradata://"
    assert td_hits[0]["quote"] in td_page
    md_page = "<html>neo4j://a@db monetdb://b@db</html>"
    md_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": md_page})
    md_hits = [item for item in md_found if item["title"] == "Public response includes a database address"]
    assert len(md_hits) == 1
    assert md_hits[0]["quote"] == "monetdb://"
    assert md_hits[0]["quote"] in md_page
    qd_page = "<html>neo4j://a@db questdb://b@db</html>"
    qd_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": qd_page})
    qd_hits = [item for item in qd_found if item["title"] == "Public response includes a database address"]
    assert len(qd_hits) == 1
    assert qd_hits[0]["quote"] == "questdb://"
    assert qd_hits[0]["quote"] in qd_page
    hs_page = "<html>neo4j://a@db hsqldb://b@db</html>"
    hs_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": hs_page})
    hs_hits = [item for item in hs_found if item["title"] == "Public response includes a database address"]
    assert len(hs_hits) == 1
    assert hs_hits[0]["quote"] == "hsqldb://"
    assert hs_hits[0]["quote"] in hs_page
    dk_page = "<html>neo4j://a@db duckdb://b@db</html>"
    dk_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": dk_page})
    dk_hits = [item for item in dk_found if item["title"] == "Public response includes a database address"]
    assert len(dk_hits) == 1
    assert dk_hits[0]["quote"] == "duckdb://"
    assert dk_hits[0]["quote"] in dk_page
    pr_page = "<html>neo4j://a@db presto://b@db</html>"
    pr_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": pr_page})
    pr_hits = [item for item in pr_found if item["title"] == "Public response includes a database address"]
    assert len(pr_hits) == 1
    assert pr_hits[0]["quote"] == "presto://"
    assert pr_hits[0]["quote"] in pr_page
    gp_page = "<html>neo4j://a@db greenplum://b@db</html>"
    gp_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": gp_page})
    gp_hits = [item for item in gp_found if item["title"] == "Public response includes a database address"]
    assert len(gp_hits) == 1
    assert gp_hits[0]["quote"] == "greenplum://"
    assert gp_hits[0]["quote"] in gp_page
    rs_page = "<html>neo4j://a@db redshift://b@db</html>"
    rs_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rs_page})
    rs_hits = [item for item in rs_found if item["title"] == "Public response includes a database address"]
    assert len(rs_hits) == 1
    assert rs_hits[0]["quote"] == "redshift://"
    assert rs_hits[0]["quote"] in rs_page
    im_page = "<html>neo4j://a@db impala://b@db</html>"
    im_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": im_page})
    im_hits = [item for item in im_found if item["title"] == "Public response includes a database address"]
    assert len(im_hits) == 1
    assert im_hits[0]["quote"] == "impala://"
    assert im_hits[0]["quote"] in im_page
    vt2_page = "<html>neo4j://a@db vitess://b@db</html>"
    vt2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": vt2_page})
    vt2_hits = [item for item in vt2_found if item["title"] == "Public response includes a database address"]
    assert len(vt2_hits) == 1
    assert vt2_hits[0]["quote"] == "vitess://"
    assert vt2_hits[0]["quote"] in vt2_page
    tn_page = "<html>neo4j://a@db trino://b@db</html>"
    tn_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": tn_page})
    tn_hits = [item for item in tn_found if item["title"] == "Public response includes a database address"]
    assert len(tn_hits) == 1
    assert tn_hits[0]["quote"] == "trino://"
    assert tn_hits[0]["quote"] in tn_page
    ae_page = "<html>neo4j://a@db aerospike://b@db</html>"
    ae_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ae_page})
    ae_hits = [item for item in ae_found if item["title"] == "Public response includes a database address"]
    assert len(ae_hits) == 1
    assert ae_hits[0]["quote"] == "aerospike://"
    assert ae_hits[0]["quote"] in ae_page
    dy_page = "<html>neo4j://a@db derby://b@db</html>"
    dy_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": dy_page})
    dy_hits = [item for item in dy_found if item["title"] == "Public response includes a database address"]
    assert len(dy_hits) == 1
    assert dy_hits[0]["quote"] == "derby://"
    assert dy_hits[0]["quote"] in dy_page
    hz_page = "<html>neo4j://a@db hazelcast://b@db</html>"
    hz_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": hz_page})
    hz_hits = [item for item in hz_found if item["title"] == "Public response includes a database address"]
    assert len(hz_hits) == 1
    assert hz_hits[0]["quote"] == "hazelcast://"
    assert hz_hits[0]["quote"] in hz_page
    du_page = "<html>neo4j://a@db druid://b@db</html>"
    du_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": du_page})
    du_hits = [item for item in du_found if item["title"] == "Public response includes a database address"]
    assert len(du_hits) == 1
    assert du_hits[0]["quote"] == "druid://"
    assert du_hits[0]["quote"] in du_page
    mx_page = "<html>neo4j://a@db maxdb://b@db</html>"
    mx_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": mx_page})
    mx_hits = [item for item in mx_found if item["title"] == "Public response includes a database address"]
    assert len(mx_hits) == 1
    assert mx_hits[0]["quote"] == "maxdb://"
    assert mx_hits[0]["quote"] in mx_page
    pn_page = "<html>neo4j://a@db pinot://b@db</html>"
    pn_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": pn_page})
    pn_hits = [item for item in pn_found if item["title"] == "Public response includes a database address"]
    assert len(pn_hits) == 1
    assert pn_hits[0]["quote"] == "pinot://"
    assert pn_hits[0]["quote"] in pn_page
    gd_page = "<html>neo4j://a@db geode://b@db</html>"
    gd_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": gd_page})
    gd_hits = [item for item in gd_found if item["title"] == "Public response includes a database address"]
    assert len(gd_hits) == 1
    assert gd_hits[0]["quote"] == "geode://"
    assert gd_hits[0]["quote"] in gd_page
    ml_page = "<html>neo4j://a@db marklogic://b@db</html>"
    ml_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ml_page})
    ml_hits = [item for item in ml_found if item["title"] == "Public response includes a database address"]
    assert len(ml_hits) == 1
    assert ml_hits[0]["quote"] == "marklogic://"
    assert ml_hits[0]["quote"] in ml_page
    sr_page = "<html>neo4j://a@db surrealdb://b@db</html>"
    sr_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sr_page})
    sr_hits = [item for item in sr_found if item["title"] == "Public response includes a database address"]
    assert len(sr_hits) == 1
    assert sr_hits[0]["quote"] == "surrealdb://"
    assert sr_hits[0]["quote"] in sr_page
    eg_page = "<html>neo4j://a@db edgedb://b@db</html>"
    eg_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": eg_page})
    eg_hits = [item for item in eg_found if item["title"] == "Public response includes a database address"]
    assert len(eg_hits) == 1
    assert eg_hits[0]["quote"] == "edgedb://"
    assert eg_hits[0]["quote"] in eg_page
    dc_page = "<html>neo4j://a@db documentdb://b@db</html>"
    dc_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": dc_page})
    dc_hits = [item for item in dc_found if item["title"] == "Public response includes a database address"]
    assert len(dc_hits) == 1
    assert dc_hits[0]["quote"] == "documentdb://"
    assert dc_hits[0]["quote"] in dc_page
    gg_page = "<html>neo4j://a@db gridgain://b@db</html>"
    gg_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": gg_page})
    gg_hits = [item for item in gg_found if item["title"] == "Public response includes a database address"]
    assert len(gg_hits) == 1
    assert gg_hits[0]["quote"] == "gridgain://"
    assert gg_hits[0]["quote"] in gg_page
    rv_page = "<html>neo4j://a@db ravendb://b@db</html>"
    rv_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rv_page})
    rv_hits = [item for item in rv_found if item["title"] == "Public response includes a database address"]
    assert len(rv_hits) == 1
    assert rv_hits[0]["quote"] == "ravendb://"
    assert rv_hits[0]["quote"] in rv_page
    fb_page = "<html>neo4j://a@db firebird://b@db</html>"
    fb_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": fb_page})
    fb_hits = [item for item in fb_found if item["title"] == "Public response includes a database address"]
    assert len(fb_hits) == 1
    assert fb_hits[0]["quote"] == "firebird://"
    assert fb_hits[0]["quote"] in fb_page
    ib_page = "<html>neo4j://a@db interbase://b@db</html>"
    ib_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ib_page})
    ib_hits = [item for item in ib_found if item["title"] == "Public response includes a database address"]
    assert len(ib_hits) == 1
    assert ib_hits[0]["quote"] == "interbase://"
    assert ib_hits[0]["quote"] in ib_page
    ms_page = "<html>neo4j://a@db memsql://b@db</html>"
    ms_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ms_page})
    ms_hits = [item for item in ms_found if item["title"] == "Public response includes a database address"]
    assert len(ms_hits) == 1
    assert ms_hits[0]["quote"] == "memsql://"
    assert ms_hits[0]["quote"] in ms_page
    ss_page = "<html>neo4j://a@db singlestore://b@db</html>"
    ss_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ss_page})
    ss_hits = [item for item in ss_found if item["title"] == "Public response includes a database address"]
    assert len(ss_hits) == 1
    assert ss_hits[0]["quote"] == "singlestore://"
    assert ss_hits[0]["quote"] in ss_page
    pc_page = "<html>neo4j://a@db percona://b@db</html>"
    pc_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": pc_page})
    pc_hits = [item for item in pc_found if item["title"] == "Public response includes a database address"]
    assert len(pc_hits) == 1
    assert pc_hits[0]["quote"] == "percona://"
    assert pc_hits[0]["quote"] in pc_page
    ct_page = "<html>neo4j://a@db citus://b@db</html>"
    ct_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ct_page})
    ct_hits = [item for item in ct_found if item["title"] == "Public response includes a database address"]
    assert len(ct_hits) == 1
    assert ct_hits[0]["quote"] == "citus://"
    assert ct_hits[0]["quote"] in ct_page
    nd_page = "<html>neo4j://a@db nuodb://b@db</html>"
    nd_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": nd_page})
    nd_hits = [item for item in nd_found if item["title"] == "Public response includes a database address"]
    assert len(nd_hits) == 1
    assert nd_hits[0]["quote"] == "nuodb://"
    assert nd_hits[0]["quote"] in nd_page
    sp_page = "<html>neo4j://a@db spark://b@db</html>"
    sp_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sp_page})
    sp_hits = [item for item in sp_found if item["title"] == "Public response includes a database address"]
    assert len(sp_hits) == 1
    assert sp_hits[0]["quote"] == "spark://"
    assert sp_hits[0]["quote"] in sp_page
    jo_page = "<html>oracle://a@db jdbc:oracle://b@db</html>"
    jo_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jo_page})
    jo_hits = [item for item in jo_found if item["title"] == "Public response includes a database address"]
    assert len(jo_hits) == 1
    assert jo_hits[0]["quote"] == "jdbc:oracle://"
    assert jo_hits[0]["quote"] in jo_page
    ora_page = "<html>oracle://a@db</html>"
    ora_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ora_page})
    ora_hits = [item for item in ora_found if item["title"] == "Public response includes a database address"]
    assert len(ora_hits) == 1
    assert ora_hits[0]["quote"] == "oracle://"
    assert ora_hits[0]["quote"] in ora_page
    js_page = "<html>sqlserver://a@db jdbc:sqlserver://b@db</html>"
    js_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": js_page})
    js_hits = [item for item in js_found if item["title"] == "Public response includes a database address"]
    assert len(js_hits) == 1
    assert js_hits[0]["quote"] == "jdbc:sqlserver://"
    assert js_hits[0]["quote"] in js_page
    sq_page = "<html>sqlserver://a@db</html>"
    sq_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sq_page})
    sq_hits = [item for item in sq_found if item["title"] == "Public response includes a database address"]
    assert len(sq_hits) == 1
    assert sq_hits[0]["quote"] == "sqlserver://"
    assert sq_hits[0]["quote"] in sq_page
    jm_page = "<html>mariadb://a@db jdbc:mariadb://b@db</html>"
    jm_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jm_page})
    jm_hits = [item for item in jm_found if item["title"] == "Public response includes a database address"]
    assert len(jm_hits) == 1
    assert jm_hits[0]["quote"] == "jdbc:mariadb://"
    assert jm_hits[0]["quote"] in jm_page
    ma_page = "<html>mariadb://a@db</html>"
    ma_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ma_page})
    ma_hits = [item for item in ma_found if item["title"] == "Public response includes a database address"]
    assert len(ma_hits) == 1
    assert ma_hits[0]["quote"] == "mariadb://"
    assert ma_hits[0]["quote"] in ma_page
    jd_page = "<html>derby://a@db jdbc:derby://b@db</html>"
    jd_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jd_page})
    jd_hits = [item for item in jd_found if item["title"] == "Public response includes a database address"]
    assert len(jd_hits) == 1
    assert jd_hits[0]["quote"] == "jdbc:derby://"
    assert jd_hits[0]["quote"] in jd_page
    dy2_page = "<html>derby://a@db</html>"
    dy2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": dy2_page})
    dy2_hits = [item for item in dy2_found if item["title"] == "Public response includes a database address"]
    assert len(dy2_hits) == 1
    assert dy2_hits[0]["quote"] == "derby://"
    assert dy2_hits[0]["quote"] in dy2_page
    jh_page = "<html>hsqldb://a@db jdbc:hsqldb://b@db</html>"
    jh_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jh_page})
    jh_hits = [item for item in jh_found if item["title"] == "Public response includes a database address"]
    assert len(jh_hits) == 1
    assert jh_hits[0]["quote"] == "jdbc:hsqldb://"
    assert jh_hits[0]["quote"] in jh_page
    hs2_page = "<html>hsqldb://a@db</html>"
    hs2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": hs2_page})
    hs2_hits = [item for item in hs2_found if item["title"] == "Public response includes a database address"]
    assert len(hs2_hits) == 1
    assert hs2_hits[0]["quote"] == "hsqldb://"
    assert hs2_hits[0]["quote"] in hs2_page
    jf_page = "<html>firebird://a@db jdbc:firebird://b@db</html>"
    jf_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jf_page})
    jf_hits = [item for item in jf_found if item["title"] == "Public response includes a database address"]
    assert len(jf_hits) == 1
    assert jf_hits[0]["quote"] == "jdbc:firebird://"
    assert jf_hits[0]["quote"] in jf_page
    fb2_page = "<html>firebird://a@db</html>"
    fb2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": fb2_page})
    fb2_hits = [item for item in fb2_found if item["title"] == "Public response includes a database address"]
    assert len(fb2_hits) == 1
    assert fb2_hits[0]["quote"] == "firebird://"
    assert fb2_hits[0]["quote"] in fb2_page
    ji_page = "<html>interbase://a@db jdbc:interbase://b@db</html>"
    ji_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ji_page})
    ji_hits = [item for item in ji_found if item["title"] == "Public response includes a database address"]
    assert len(ji_hits) == 1
    assert ji_hits[0]["quote"] == "jdbc:interbase://"
    assert ji_hits[0]["quote"] in ji_page
    ib2_page = "<html>interbase://a@db</html>"
    ib2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ib2_page})
    ib2_hits = [item for item in ib2_found if item["title"] == "Public response includes a database address"]
    assert len(ib2_hits) == 1
    assert ib2_hits[0]["quote"] == "interbase://"
    assert ib2_hits[0]["quote"] in ib2_page
    jm_page = "<html>memsql://a@db jdbc:memsql://b@db</html>"
    jm_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jm_page})
    jm_hits = [item for item in jm_found if item["title"] == "Public response includes a database address"]
    assert len(jm_hits) == 1
    assert jm_hits[0]["quote"] == "jdbc:memsql://"
    assert jm_hits[0]["quote"] in jm_page
    ms2_page = "<html>memsql://a@db</html>"
    ms2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ms2_page})
    ms2_hits = [item for item in ms2_found if item["title"] == "Public response includes a database address"]
    assert len(ms2_hits) == 1
    assert ms2_hits[0]["quote"] == "memsql://"
    assert ms2_hits[0]["quote"] in ms2_page
    js_page = "<html>singlestore://a@db jdbc:singlestore://b@db</html>"
    js_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": js_page})
    js_hits = [item for item in js_found if item["title"] == "Public response includes a database address"]
    assert len(js_hits) == 1
    assert js_hits[0]["quote"] == "jdbc:singlestore://"
    assert js_hits[0]["quote"] in js_page
    ss2_page = "<html>singlestore://a@db</html>"
    ss2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ss2_page})
    ss2_hits = [item for item in ss2_found if item["title"] == "Public response includes a database address"]
    assert len(ss2_hits) == 1
    assert ss2_hits[0]["quote"] == "singlestore://"
    assert ss2_hits[0]["quote"] in ss2_page
    jp_page = "<html>percona://a@db jdbc:percona://b@db</html>"
    jp_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jp_page})
    jp_hits = [item for item in jp_found if item["title"] == "Public response includes a database address"]
    assert len(jp_hits) == 1
    assert jp_hits[0]["quote"] == "jdbc:percona://"
    assert jp_hits[0]["quote"] in jp_page
    pc2_page = "<html>percona://a@db</html>"
    pc2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": pc2_page})
    pc2_hits = [item for item in pc2_found if item["title"] == "Public response includes a database address"]
    assert len(pc2_hits) == 1
    assert pc2_hits[0]["quote"] == "percona://"
    assert pc2_hits[0]["quote"] in pc2_page
    jc_page = "<html>citus://a@db jdbc:citus://b@db</html>"
    jc_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jc_page})
    jc_hits = [item for item in jc_found if item["title"] == "Public response includes a database address"]
    assert len(jc_hits) == 1
    assert jc_hits[0]["quote"] == "jdbc:citus://"
    assert jc_hits[0]["quote"] in jc_page
    ct2_page = "<html>citus://a@db</html>"
    ct2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ct2_page})
    ct2_hits = [item for item in ct2_found if item["title"] == "Public response includes a database address"]
    assert len(ct2_hits) == 1
    assert ct2_hits[0]["quote"] == "citus://"
    assert ct2_hits[0]["quote"] in ct2_page
    jn_page = "<html>nuodb://a@db jdbc:nuodb://b@db</html>"
    jn_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jn_page})
    jn_hits = [item for item in jn_found if item["title"] == "Public response includes a database address"]
    assert len(jn_hits) == 1
    assert jn_hits[0]["quote"] == "jdbc:nuodb://"
    assert jn_hits[0]["quote"] in jn_page
    nu2_page = "<html>nuodb://a@db</html>"
    nu2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": nu2_page})
    nu2_hits = [item for item in nu2_found if item["title"] == "Public response includes a database address"]
    assert len(nu2_hits) == 1
    assert nu2_hits[0]["quote"] == "nuodb://"
    assert nu2_hits[0]["quote"] in nu2_page
    jsp_page = "<html>spark://a@db jdbc:spark://b@db</html>"
    jsp_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jsp_page})
    jsp_hits = [item for item in jsp_found if item["title"] == "Public response includes a database address"]
    assert len(jsp_hits) == 1
    assert jsp_hits[0]["quote"] == "jdbc:spark://"
    assert jsp_hits[0]["quote"] in jsp_page
    sp2_page = "<html>spark://a@db</html>"
    sp2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": sp2_page})
    sp2_hits = [item for item in sp2_found if item["title"] == "Public response includes a database address"]
    assert len(sp2_hits) == 1
    assert sp2_hits[0]["quote"] == "spark://"
    assert sp2_hits[0]["quote"] in sp2_page
    jn4_page = "<html>neo4j://a@db jdbc:neo4j://b@db</html>"
    jn4_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jn4_page})
    jn4_hits = [item for item in jn4_found if item["title"] == "Public response includes a database address"]
    assert len(jn4_hits) == 1
    assert jn4_hits[0]["quote"] == "jdbc:neo4j://"
    assert jn4_hits[0]["quote"] in jn4_page
    n42_page = "<html>neo4j://a@db</html>"
    n42_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": n42_page})
    n42_hits = [item for item in n42_found if item["title"] == "Public response includes a database address"]
    assert len(n42_hits) == 1
    assert n42_hits[0]["quote"] == "neo4j://"
    assert n42_hits[0]["quote"] in n42_page
    jms_page = "<html>mssql://a@db jdbc:mssql://b@db</html>"
    jms_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jms_page})
    jms_hits = [item for item in jms_found if item["title"] == "Public response includes a database address"]
    assert len(jms_hits) == 1
    assert jms_hits[0]["quote"] == "jdbc:mssql://"
    assert jms_hits[0]["quote"] in jms_page
    ms3_page = "<html>mssql://a@db</html>"
    ms3_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ms3_page})
    ms3_hits = [item for item in ms3_found if item["title"] == "Public response includes a database address"]
    assert len(ms3_hits) == 1
    assert ms3_hits[0]["quote"] == "mssql://"
    assert ms3_hits[0]["quote"] in ms3_page
    jr_page = "<html>redis://a@db jdbc:redis://b@db</html>"
    jr_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jr_page})
    jr_hits = [item for item in jr_found if item["title"] == "Public response includes a database address"]
    assert len(jr_hits) == 1
    assert jr_hits[0]["quote"] == "jdbc:redis://"
    assert jr_hits[0]["quote"] in jr_page
    rd2_page = "<html>redis://a@db</html>"
    rd2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rd2_page})
    rd2_hits = [item for item in rd2_found if item["title"] == "Public response includes a database address"]
    assert len(rd2_hits) == 1
    assert rd2_hits[0]["quote"] == "redis://"
    assert rd2_hits[0]["quote"] in rd2_page
    jrv_page = "<html>ravendb://a@db jdbc:ravendb://b@db</html>"
    jrv_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jrv_page})
    jrv_hits = [item for item in jrv_found if item["title"] == "Public response includes a database address"]
    assert len(jrv_hits) == 1
    assert jrv_hits[0]["quote"] == "jdbc:ravendb://"
    assert jrv_hits[0]["quote"] in jrv_page
    rv2_page = "<html>ravendb://a@db</html>"
    rv2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": rv2_page})
    rv2_hits = [item for item in rv2_found if item["title"] == "Public response includes a database address"]
    assert len(rv2_hits) == 1
    assert rv2_hits[0]["quote"] == "ravendb://"
    assert rv2_hits[0]["quote"] in rv2_page
    jgg_page = "<html>gridgain://a@db jdbc:gridgain://b@db</html>"
    jgg_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jgg_page})
    jgg_hits = [item for item in jgg_found if item["title"] == "Public response includes a database address"]
    assert len(jgg_hits) == 1
    assert jgg_hits[0]["quote"] == "jdbc:gridgain://"
    assert jgg_hits[0]["quote"] in jgg_page
    gg2_page = "<html>gridgain://a@db</html>"
    gg2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": gg2_page})
    gg2_hits = [item for item in gg2_found if item["title"] == "Public response includes a database address"]
    assert len(gg2_hits) == 1
    assert gg2_hits[0]["quote"] == "gridgain://"
    assert gg2_hits[0]["quote"] in gg2_page
    jdd_page = "<html>documentdb://a@db jdbc:documentdb://b@db</html>"
    jdd_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jdd_page})
    jdd_hits = [item for item in jdd_found if item["title"] == "Public response includes a database address"]
    assert len(jdd_hits) == 1
    assert jdd_hits[0]["quote"] == "jdbc:documentdb://"
    assert jdd_hits[0]["quote"] in jdd_page
    dd2_page = "<html>documentdb://a@db</html>"
    dd2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": dd2_page})
    dd2_hits = [item for item in dd2_found if item["title"] == "Public response includes a database address"]
    assert len(dd2_hits) == 1
    assert dd2_hits[0]["quote"] == "documentdb://"
    assert dd2_hits[0]["quote"] in dd2_page
    jed_page = "<html>edgedb://a@db jdbc:edgedb://b@db</html>"
    jed_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jed_page})
    jed_hits = [item for item in jed_found if item["title"] == "Public response includes a database address"]
    assert len(jed_hits) == 1
    assert jed_hits[0]["quote"] == "jdbc:edgedb://"
    assert jed_hits[0]["quote"] in jed_page
    ed2_page = "<html>edgedb://a@db</html>"
    ed2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ed2_page})
    ed2_hits = [item for item in ed2_found if item["title"] == "Public response includes a database address"]
    assert len(ed2_hits) == 1
    assert ed2_hits[0]["quote"] == "edgedb://"
    assert ed2_hits[0]["quote"] in ed2_page
    jsu_page = "<html>surrealdb://a@db jdbc:surrealdb://b@db</html>"
    jsu_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jsu_page})
    jsu_hits = [item for item in jsu_found if item["title"] == "Public response includes a database address"]
    assert len(jsu_hits) == 1
    assert jsu_hits[0]["quote"] == "jdbc:surrealdb://"
    assert jsu_hits[0]["quote"] in jsu_page
    su2_page = "<html>surrealdb://a@db</html>"
    su2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": su2_page})
    su2_hits = [item for item in su2_found if item["title"] == "Public response includes a database address"]
    assert len(su2_hits) == 1
    assert su2_hits[0]["quote"] == "surrealdb://"
    assert su2_hits[0]["quote"] in su2_page
    jml_page = "<html>marklogic://a@db jdbc:marklogic://b@db</html>"
    jml_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jml_page})
    jml_hits = [item for item in jml_found if item["title"] == "Public response includes a database address"]
    assert len(jml_hits) == 1
    assert jml_hits[0]["quote"] == "jdbc:marklogic://"
    assert jml_hits[0]["quote"] in jml_page
    ml2_page = "<html>marklogic://a@db</html>"
    ml2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ml2_page})
    ml2_hits = [item for item in ml2_found if item["title"] == "Public response includes a database address"]
    assert len(ml2_hits) == 1
    assert ml2_hits[0]["quote"] == "marklogic://"
    assert ml2_hits[0]["quote"] in ml2_page
    jge_page = "<html>geode://a@db jdbc:geode://b@db</html>"
    jge_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jge_page})
    jge_hits = [item for item in jge_found if item["title"] == "Public response includes a database address"]
    assert len(jge_hits) == 1
    assert jge_hits[0]["quote"] == "jdbc:geode://"
    assert jge_hits[0]["quote"] in jge_page
    ge2_page = "<html>geode://a@db</html>"
    ge2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": ge2_page})
    ge2_hits = [item for item in ge2_found if item["title"] == "Public response includes a database address"]
    assert len(ge2_hits) == 1
    assert ge2_hits[0]["quote"] == "geode://"
    assert ge2_hits[0]["quote"] in ge2_page
    jpi_page = "<html>pinot://a@db jdbc:pinot://b@db</html>"
    jpi_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jpi_page})
    jpi_hits = [item for item in jpi_found if item["title"] == "Public response includes a database address"]
    assert len(jpi_hits) == 1
    assert jpi_hits[0]["quote"] == "jdbc:pinot://"
    assert jpi_hits[0]["quote"] in jpi_page
    pi2_page = "<html>pinot://a@db</html>"
    pi2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": pi2_page})
    pi2_hits = [item for item in pi2_found if item["title"] == "Public response includes a database address"]
    assert len(pi2_hits) == 1
    assert pi2_hits[0]["quote"] == "pinot://"
    assert pi2_hits[0]["quote"] in pi2_page
    jmx_page = "<html>maxdb://a@db jdbc:maxdb://b@db</html>"
    jmx_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jmx_page})
    jmx_hits = [item for item in jmx_found if item["title"] == "Public response includes a database address"]
    assert len(jmx_hits) == 1
    assert jmx_hits[0]["quote"] == "jdbc:maxdb://"
    assert jmx_hits[0]["quote"] in jmx_page
    mx2_page = "<html>maxdb://a@db</html>"
    mx2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": mx2_page})
    mx2_hits = [item for item in mx2_found if item["title"] == "Public response includes a database address"]
    assert len(mx2_hits) == 1
    assert mx2_hits[0]["quote"] == "maxdb://"
    assert mx2_hits[0]["quote"] in mx2_page
    jdu_page = "<html>druid://a@db jdbc:druid://b@db</html>"
    jdu_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jdu_page})
    jdu_hits = [item for item in jdu_found if item["title"] == "Public response includes a database address"]
    assert len(jdu_hits) == 1
    assert jdu_hits[0]["quote"] == "jdbc:druid://"
    assert jdu_hits[0]["quote"] in jdu_page
    du2_page = "<html>druid://a@db</html>"
    du2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": du2_page})
    du2_hits = [item for item in du2_found if item["title"] == "Public response includes a database address"]
    assert len(du2_hits) == 1
    assert du2_hits[0]["quote"] == "druid://"
    assert du2_hits[0]["quote"] in du2_page
    jhz_page = "<html>hazelcast://a@db jdbc:hazelcast://b@db</html>"
    jhz_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jhz_page})
    jhz_hits = [item for item in jhz_found if item["title"] == "Public response includes a database address"]
    assert len(jhz_hits) == 1
    assert jhz_hits[0]["quote"] == "jdbc:hazelcast://"
    assert jhz_hits[0]["quote"] in jhz_page
    hz2_page = "<html>hazelcast://a@db</html>"
    hz2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": hz2_page})
    hz2_hits = [item for item in hz2_found if item["title"] == "Public response includes a database address"]
    assert len(hz2_hits) == 1
    assert hz2_hits[0]["quote"] == "hazelcast://"
    assert hz2_hits[0]["quote"] in hz2_page
    jas_page = "<html>aerospike://a@db jdbc:aerospike://b@db</html>"
    jas_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jas_page})
    jas_hits = [item for item in jas_found if item["title"] == "Public response includes a database address"]
    assert len(jas_hits) == 1
    assert jas_hits[0]["quote"] == "jdbc:aerospike://"
    assert jas_hits[0]["quote"] in jas_page
    as2_page = "<html>aerospike://a@db</html>"
    as2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": as2_page})
    as2_hits = [item for item in as2_found if item["title"] == "Public response includes a database address"]
    assert len(as2_hits) == 1
    assert as2_hits[0]["quote"] == "aerospike://"
    assert as2_hits[0]["quote"] in as2_page
    jtr_page = "<html>trino://a@db jdbc:trino://b@db</html>"
    jtr_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": jtr_page})
    jtr_hits = [item for item in jtr_found if item["title"] == "Public response includes a database address"]
    assert len(jtr_hits) == 1
    assert jtr_hits[0]["quote"] == "jdbc:trino://"
    assert jtr_hits[0]["quote"] in jtr_page
    tr2_page = "<html>trino://a@db</html>"
    tr2_found = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": tr2_page})
    tr2_hits = [item for item in tr2_found if item["title"] == "Public response includes a database address"]
    assert len(tr2_hits) == 1
    assert tr2_hits[0]["quote"] == "trino://"
    assert tr2_hits[0]["quote"] in tr2_page
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response includes a database address" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"mongodb://app@db/app"}',
        }
    )
    assert all(item["title"] != "Public response includes a database address" for item in spec)


def test_stack_trace_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>Traceback (most recent call last):\n  File app.py</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a stack trace"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "Traceback"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 500, "body": "Traceback (most recent call last):"})
    static_hits = [item for item in script if item["title"] == "Public response shows a stack trace"]
    assert len(static_hits) == 1
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a stack trace" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"Traceback"}',
        }
    )
    assert all(item["title"] != "Public response shows a stack trace" for item in spec)


def test_syntax_error_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>SyntaxError: bad token</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a syntax error"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "SyntaxError"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 500, "body": "SyntaxError: bad token"})
    static_hits = [item for item in script if item["title"] == "Public response shows a syntax error"]
    assert len(static_hits) == 1
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a syntax error" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"SyntaxError"}',
        }
    )
    assert all(item["title"] != "Public response shows a syntax error" for item in spec)


def test_certificate_header_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>-----BEGIN CERTIFICATE-----\nMIIB</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response exposes a certificate"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "-----BEGIN CERTIFICATE-----"
    assert hits[0]["quote"] in page
    script = detect(
        {"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "-----BEGIN CERTIFICATE-----\nMIIB"}
    )
    static_hits = [item for item in script if item["title"] == "Public response exposes a certificate"]
    assert len(static_hits) == 1
    request = detect(
        {"url": "http://vampi:5000/ui/", "status": 200, "body": "-----BEGIN CERTIFICATE REQUEST-----"}
    )
    assert all(item["title"] != "Public response exposes a certificate" for item in request)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response exposes a certificate" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"-----BEGIN CERTIFICATE-----"}',
        }
    )
    assert all(item["title"] != "Public response exposes a certificate" for item in spec)


def test_query_schema_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = '{"data":{"__schema":{"types":[]}}}'
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a query schema"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "__schema"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "query { __schema { types { name } } }"})
    static_hits = [item for item in script if item["title"] == "Public response shows a query schema"]
    assert len(static_hits) == 1
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a query schema" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"__schema"}',
        }
    )
    assert all(item["title"] != "Public response shows a query schema" for item in spec)


def test_framework_debugger_is_quoted_from_the_body(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><h1>Werkzeug Debugger</h1></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 500, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a framework debugger"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "Werkzeug"
    assert hits[0]["quote"] in page
    header_only = detect(
        {
            "url": "http://vampi:5000/",
            "status": 200,
            "body": "<html></html>",
            "headers": {"Server": "Werkzeug/2.2.2"},
        }
    )
    assert all(item["title"] != "Public response shows a framework debugger" for item in header_only)
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "Werkzeug Debugger"})
    assert all(item["title"] != "Public response shows a framework debugger" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a framework debugger" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"Werkzeug"}',
        }
    )
    assert all(item["title"] != "Public response shows a framework debugger" for item in spec)


def test_reference_error_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>ReferenceError: name is not defined</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a reference error"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "ReferenceError"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "ReferenceError: name is not defined"})
    assert all(item["title"] != "Public response shows a reference error" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a reference error" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"ReferenceError"}',
        }
    )
    assert all(item["title"] != "Public response shows a reference error" for item in spec)


def test_type_error_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>TypeError: value is not a function</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a type error"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "TypeError"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "TypeError: value is not a function"})
    assert all(item["title"] != "Public response shows a type error" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a type error" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"TypeError"}',
        }
    )
    assert all(item["title"] != "Public response shows a type error" for item in spec)


def test_range_error_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>RangeError: invalid length</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a range error"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "RangeError"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "RangeError: invalid length"})
    assert all(item["title"] != "Public response shows a range error" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a range error" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"RangeError"}',
        }
    )
    assert all(item["title"] != "Public response shows a range error" for item in spec)


def test_uri_error_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>URIError: bad URI</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a URI error"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "URIError"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "URIError: bad URI"})
    assert all(item["title"] != "Public response shows a URI error" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a URI error" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"URIError"}',
        }
    )
    assert all(item["title"] != "Public response shows a URI error" for item in spec)


def test_eval_error_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><pre>EvalError: bad call</pre></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows an eval error"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "EvalError"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "EvalError: bad call"})
    assert all(item["title"] != "Public response shows an eval error" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows an eval error" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"EvalError"}',
        }
    )
    assert all(item["title"] != "Public response shows an eval error" for item in spec)


def test_server_error_page_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><h1>Internal Server Error</h1></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 500, "body": page})
    hits = [item for item in found if item["title"] == "Public response shows a server error page"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "Internal Server Error"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 500, "body": "Internal Server Error"})
    assert all(item["title"] != "Public response shows a server error page" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response shows a server error page" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"Internal Server Error"}',
        }
    )
    assert all(item["title"] != "Public response shows a server error page" for item in spec)


def test_database_console_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    page = "<html><title>phpMyAdmin</title></html>"
    found = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": page})
    hits = [item for item in found if item["title"] == "Public response names a database console"]
    assert len(hits) == 1
    assert hits[0]["quote"] == "phpMyAdmin"
    assert hits[0]["quote"] in page
    script = detect({"url": "http://vampi:5000/ui/app.js", "status": 200, "body": "phpMyAdmin"})
    assert all(item["title"] != "Public response names a database console" for item in script)
    plain = detect({"url": "http://vampi:5000/ui/", "status": 200, "body": "<html></html>"})
    assert all(item["title"] != "Public response names a database console" for item in plain)
    spec = detect(
        {
            "url": "http://vampi:5000/openapi.json",
            "status": 200,
            "body": '{"openapi":"3.0.0","paths":{},"note":"phpMyAdmin"}',
        }
    )
    assert all(item["title"] != "Public response names a database console" for item in spec)


def test_a_public_admin_role_uses_the_admin_flag_title(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = '{"user":"ada","role": "admin"}'
    found = detect({"url": "http://vampi:5000/users/v1", "status": 200, "body": body})
    assert found[0]["title"] == "Public response shows an admin flag"
    assert found[0]["quote"] == '"role": "admin"'
    assert found[0]["quote"] in body
    user = detect({"url": "http://vampi:5000/users/v1", "status": 200, "body": '{"role":"user"}'})
    assert all(item["title"] != "Public response shows an admin flag" for item in user)
    both = detect(
        {
            "url": "http://vampi:5000/users/v1/_debug",
            "status": 200,
            "body": '{"admin": true,"role":"admin"}',
        }
    )
    assert [item["quote"] for item in both if item["title"] == "Public response shows an admin flag"] == [
        '"admin": true'
    ]
    spec = '{"openapi":"3.0.1","paths":{"/x":{"get":{}}},"role":"admin"}'
    assert detect({"url": "http://vampi:5000/openapi.json", "status": 200, "body": spec}) == []


def test_a_public_admin_flag_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = '{"users":[{"admin": false},{"admin": true}]}'
    found = detect({"url": "http://vampi:5000/users/v1/_debug", "status": 200, "body": body})
    assert found[0]["title"] == "Public response shows an admin flag"
    assert found[0]["quote"] == '"admin": true'


def test_a_public_dotenv_line_quotes_the_key_only(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "PORT=80\nexport API_KEY=present\nSECRET=present\n"
    found = detect({"url": "http://vampi:5000/.env", "status": 200, "body": body})
    assert found[0]["title"] == "Public response includes a secret field"
    assert found[0]["quote"] == "API_KEY="
    assert "present" not in found[0]["quote"]
    assert all(item["quote"] != "SECRET=" for item in found)
    assert all(item["quote"] != "PORT=" for item in found)
    redacted = detect({"url": "http://vampi:5000/.env", "status": 200, "body": "PASSWORD=[REDACTED]\n"})
    assert redacted[0]["quote"] == "PASSWORD="
    spec = '{"openapi":"3.0.1","paths":{"/x":{"get":{}}}}\nAPI_KEY=example\n'
    assert detect({"url": "http://vampi:5000/openapi.json", "status": 200, "body": spec}) == []
    page = "<!DOCTYPE html><html>API_KEY=example</html>"
    assert detect({"url": "http://vampi:5000/", "status": 200, "body": page}) == []


def test_a_public_token_field_is_quoted(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    for key in ("auth_token", "access_token", "api_key"):
        body = '{"user":"ada","' + key + '":"present"}'
        found = detect({"url": "http://vampi:5000/session", "status": 200, "body": body})
        assert found[0]["title"] == "Public response includes a secret field"
        assert found[0]["quote"] == '"' + key + '":'
        assert found[0]["quote"] in body
    spec = (
        '{"openapi":"3.0.1","paths":{"/x":{"get":{}}},'
        '"auth_token":"example","access_token":"example","api_key":"example"}'
    )
    assert detect({"url": "http://vampi:5000/openapi.json", "status": 200, "body": spec}) == []


def test_more_secret_keys_quote_the_key_only(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    for key in ("private_key", "refresh_token", "client_secret", "id_token"):
        body = '{"user":"ada","' + key + '":"present"}'
        found = detect({"url": "http://vampi:5000/session", "status": 200, "body": body})
        secrets = [item for item in found if item["title"] == "Public response includes a secret field"]
        assert len(secrets) == 1
        assert secrets[0]["quote"] == '"' + key + '":'
        assert "present" not in secrets[0]["quote"]
    both = detect(
        {
            "url": "http://vampi:5000/session",
            "status": 200,
            "body": '{"password":"present","private_key":"present"}',
        }
    )
    quotes = [item["quote"] for item in both if item["title"] == "Public response includes a secret field"]
    assert quotes == ['"password":']
    page = detect(
        {
            "url": "http://vampi:5000/ui/",
            "status": 200,
            "body": '<html>{"private_key":"present"}</html>',
        }
    )
    assert all(item["title"] != "Public response includes a secret field" for item in page)
    script = detect(
        {"url": "http://vampi:5000/ui/app.js", "status": 200, "body": '{"private_key":"present"}'}
    )
    assert all(item["title"] != "Public response includes a secret field" for item in script)
    flag = detect(
        {"url": "http://vampi:5000/session", "status": 200, "body": '{"vulnerable": true}'}
    )
    assert all(item["quote"] != '"vulnerable":' for item in flag)


def test_api_document_examples_are_not_a_data_leak():
    body = '{"openapi":"3.0.1","paths":{"/x":{"get":{}}},"email":"mail1@mail.com","password":"pass1"}'
    assert detect({"url": LAB_ORIGIN + "/openapi.json", "status": 200, "body": body}) == []


def test_page_link_stays_on_the_same_origin():
    body = '<link href="./swagger-ui.css" /><a href="http://evil.example/admin">'
    assert mentioned_paths({"url": LAB_ORIGIN + "/ui/", "body": body}) == ["/ui/swagger-ui.css"]


def test_a_single_quoted_href_and_src_are_read():
    body = "<a href='/files/notes.txt'></a><script src='./app.js'></script><a href=\"/keep.js\"></a>"
    assert mentioned_paths({"url": LAB_ORIGIN + "/ui/", "body": body}) == [
        "/files/notes.txt",
        "/ui/app.js",
        "/keep.js",
    ]


def test_long_error_title_still_yields_a_verbatim_quote(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "<title>" + ("x" * 300) + "sqlalchemy.exc.OperationalError: no such table</title>"
    found = detect({"url": "http://vampi:5000/users/v1", "status": 500, "body": body})
    assert found[0]["quote"] in body
    assert "OperationalError" in found[0]["quote"]
    assert len(found[0]["quote"]) <= 200


def test_server_error_quote_is_copied_from_the_response(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    body = "<title>sqlalchemy.exc.OperationalError: no such table: users</title>"
    found = detect({"url": "http://vampi:5000/users/v1", "status": 500, "body": body})
    assert found[0]["title"] == "Server error exposes an internal exception"
    assert found[0]["quote"] in body


def test_an_account_name_on_another_response_is_quoted_once():
    users = {
        "url": "http://juice-shop:3000/users",
        "status": 200,
        "body": '{"username":"ada","email":"ada@example.com"}',
    }
    catalog = {
        "url": "http://juice-shop:3000/items",
        "status": 200,
        "body": '{"title":"one","user":"ada"}',
    }
    spec = {
        "url": "http://juice-shop:3000/openapi.json",
        "status": 200,
        "body": '{"openapi":"3.0.0","paths":{"/x":{"get":{}}},"user":"ada"}',
    }
    page = {
        "url": "http://juice-shop:3000/ui/",
        "status": 200,
        "body": '<!DOCTYPE html><html>"user":"ada"</html>',
    }
    item = echoed_account([users, spec, page, catalog], set())
    assert item["location"] == "http://juice-shop:3000/items"
    assert item["quote"] == '"user":"ada"'
    assert len(item["quote"]) <= 80
    assert echoed_account([users], set()) is None
    assert echoed_account([users, catalog], {"http://juice-shop:3000/items"}) is None


def test_external_url_is_ignored():
    assert (
        detect(
            {
                "url": "http://example.com/ftp/acquisitions.md",
                "status": 200,
                "body": "This document is confidential!",
            }
        )
        == []
    )
