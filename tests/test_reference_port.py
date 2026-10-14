# SPDX-FileCopyrightText: 2026 crossVault GmbH
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the shapes the reference rules catch (and keep), one group per change.

Every token is synthetic and assembled at runtime; every person is made up.
"""

import json

import pytest

from redact_transcripts import Config, Redactor, StreamRedactor, redact_bytes

R = Redactor(config=Config(ipv4_keep=frozenset(), email_keep_domains=()))
M = "FAKEfake0123456789Zz" + "QqRr9876WwXx54Yy"  # 36 characters, mixed case and digits
GHP = "gh" + "p_" + M
AKIA = "AK" + "IA" + "FAKEFAKE01234567"
XAI = "xa" + "i-" + M + M + "AbCdEfGh"


def red(text):
    return R.redact_text(text)


def jsonl(obj_or_lines):
    raw = obj_or_lines if isinstance(obj_or_lines, str) else json.dumps(obj_or_lines) + "\n"
    out, report = redact_bytes(raw.encode(), format="jsonl", redactor=R)
    return out.decode(), report


# --- JSON-escaped keys and values ----------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        'out: {\\"k\\": \\"\\u0067' + GHP[1:] + '\\"}',  # `\u0067hp_…` inside escaped JSON
        "url 1\\/\\/0" + M + M,  # a `1//` refresh token with JSON-escaped slashes
        '{\\"\\u0074oken\\": \\"' + GHP + '\\"}',
    ],
)
def test_keys_spelled_with_json_escapes(text):
    assert M[4:20] not in red(text)


@pytest.mark.parametrize(
    "text,secret",
    [
        ('PASSWORD = \\"FAKE-correct-horse\\"', "FAKE-correct-horse"),
        ('{\\"password\\": \\"FAKE pass phrase\\"}', "FAKE pass phrase"),
        ('cfg = {\\\\\\"token\\\\\\": \\\\\\"FAKEtok3n-EXAMPLE\\\\\\"}', "FAKEtok3n-EXAMPLE"),
    ],
)
def test_escaped_quoted_assignments_at_any_depth(text, secret):
    assert secret not in red(text)


@pytest.mark.parametrize("text", ['DB_PASSWORD = \\"${DB_PASSWORD}\\"', '{\\"token\\": \\"<your token>\\"}'])
def test_escaped_placeholders_stay(text):
    assert red(text) == text


# --- home paths ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,user",
    [
        ("~/.claude/projects/-home-fakealice-myproj/1.jsonl", "fakealice"),
        ("projects/-Users-fakebob-src-app", "fakebob"),
        ("projects/C--Users-fakebob-proj", "fakebob"),
        ("projects/-mnt-c-Users-fakebob-proj", "fakebob"),
        ("open ?path=%2Fhome%2Ffakealice%2Fsrc", "fakealice"),
        ("file:///home/fakealice/notes.txt", "fakealice"),
        ("vscode-remote://ssh-remote%2Bbox/home/fakealice/src", "fakealice"),
        ("file://wsl.localhost/Ubuntu/home/fakealice/x", "fakealice"),
        ("\\\\wsl$\\Ubuntu\\home\\fakealice\\x", "fakealice"),
        ("C:\\users\\fakebob\\x", "fakebob"),
        ("C:/Users/fakebob/x", "fakebob"),
        ("c%3A%5Cusers%5Cfakebob%5Cx", "fakebob"),
        ("/home/jürgenfake/src", "jürgenfake"),
        ("/mnt/c/Users/fakebob/src", "fakebob"),
        ("/c/Users/fakebob/src", "fakebob"),
        ("cd /c/users/fakebob/src", "fakebob"),
        ("ls /users/fakebob/Documents", "fakebob"),
        ("/home/fakealice/home/fakebob/x", "fakebob"),
    ],
)
def test_home_path_forms_lose_the_user(text, user):
    out = red(text)
    assert user not in out and "[USER]" in out, out


@pytest.mark.parametrize(
    "text",
    [
        "a stay-at-home-mom blog",
        "pass --home-dir /tmp",
        "GET /users/fakebob HTTP/1.1",
        "https://example.com/users/fakebob/repos",
        "see src%2Fhome%2Fx",
        "https://host.example/home/docs",
    ],
)
def test_home_path_look_alikes_stay(text):
    assert red(text) == text


def test_lower_case_git_bash_home_without_a_path_is_still_kept():
    # Pending in the reference rules: a bare `/c/users/<user>` (no further segment) is kept.
    assert red("/c/users/fakebob") == "/c/users/fakebob"


# --- headers, signatures, command lines ----------------------------------------------------------


@pytest.mark.parametrize(
    "text,secret",
    [
        ('Digest username="fake", response="6629fae49393a05397450978507c4ef1"', "6629fae4"),
        ('Digest username="fake", cnonce="0a4f113bFAKE"', "0a4f113bFAKE"),
        ("https://b.example/k?X-Amz-Signature=" + "fe5f80f77d5fa3be" * 4 + "&x=1", "fe5f80f77d5fa3be"),
        ("x?X-Amz-Security-Token=FQoGZXIvYXdzEFAKEexample0123456789&y", "FQoGZXIvYXdzEFAKE"),
        ("Signature=AbCdEf0123456789FAKEsig%2Bx", "AbCdEf0123456789"),
        ("mysql -u root -pFAKEpass1 shop", "FAKEpass1"),
        ("mysqldump -p'FAKE pass' shop", "FAKE pass"),
        ("curl -u fakeuser:FAKEpw0rd https://x.example", "FAKEpw0rd"),
        ("--db-password 'FAKE-pw'", "FAKE-pw"),
        ("DB_PASS=FAKEpw ./run", "FAKEpw"),
        ("Authorization:\n    Bearer FAKE-EXAMPLE-0000-token", "FAKE-EXAMPLE-0000"),
    ],
)
def test_credentials_on_headers_and_command_lines(text, secret):
    assert secret not in red(text)


@pytest.mark.parametrize(
    "text",
    [
        "mkdir -p build",
        "signature=hmac_sha256",
        "docker run -u node:node img",
        "use the --password flag",
        "pwd=/home/[USER]/src",
        "docker run -u 1000:1000 img",
    ],
)
def test_command_line_look_alikes_stay(text):
    assert red(text) == text


# --- IPv6 and MAC --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["fe80::1ff:fe23:4567:890a", "2001:db8:85a3::8a2e:370:7334", "aa:bb:cc:dd:ee:0f"]
)
def test_ipv6_and_mac(text):
    assert red("host " + text + " up") != "host " + text + " up"


@pytest.mark.parametrize("text", ["file.py:26:3", "12:30:45", "std::vector<int>", "ab:cd"])
def test_ipv6_look_alikes_stay(text):
    assert red(text) == text


# --- JWT -----------------------------------------------------------------------------------------


def _b64url(obj):
    import base64

    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def test_bare_jwt_is_redacted_whole():
    jwt = _b64url({"alg": "HS256"}) + "." + _b64url({"sub": "FAKE"}) + "." + "FAKEsig" + M[:20]
    out = red("token in log: " + jwt + " end")
    assert out == "token in log: [REDACTED:secret.jwt] end"


def test_dotted_base64_without_a_jose_header_stays():
    text = _b64url({"name": "fake"}) + "." + _b64url({"x": 1}) + ".abcdefgh"
    assert red(text) == text


# --- private keys --------------------------------------------------------------------------------

BODY = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "FAKEEXAMPLE" * 3, "NOTAREALKEY" * 5 + "AbCd"]


def test_private_key_split_over_jsonl_records():
    lines = (
        json.dumps({"out": "-----BEGIN PRIVATE KEY-----\n" + BODY[0]})
        + "\n"
        + json.dumps({"out": BODY[1] + "\n-----END PRIVATE KEY-----\ndone"})
        + "\n"
    )
    out, report = jsonl(lines)
    assert "FAKEEXAMPLE" not in out and "NOTAREALKEY" not in out and "done" in out
    assert report.rules.get("secret.private_key") == 2


def test_private_key_as_an_array_of_lines():
    out, _ = jsonl({"lines": ["-----BEGIN RSA PRIVATE KEY-----", *BODY, "-----END RSA PRIVATE KEY-----"]})
    assert "FAKEEXAMPLE" not in out and "NOTAREALKEY" not in out


def test_private_key_printed_as_a_quoted_list():
    text = "['-----BEGIN PRIVATE KEY-----', '" + BODY[0] + "', '-----END PRIVATE KEY-----']"
    assert "FAKEEXAMPLE" not in red(text)


def test_lone_begin_marker_in_code_is_redacted():
    assert "BEGIN" not in red('if s.startswith("-----BEGIN PRIVATE KEY-----"):')


# --- deep nesting --------------------------------------------------------------------------------


def test_a_line_too_deep_to_decode_is_redacted_fail_closed():
    line = '{"a":' * 700 + '"' + GHP + ' FAKE note"' + "}" * 700 + "\n"
    out, report = jsonl(line)
    assert M not in out and "FAKE note" not in out
    assert report.rules.get("secret.deep_nesting") == 1
    json.loads(out)  # still JSON, at full depth


# --- vendor keys: back to back, names ------------------------------------------------------------


@pytest.mark.parametrize("joint", ["", "-", "_"])
def test_keys_written_back_to_back(joint):
    out = red("k " + GHP + joint + AKIA + " z")
    assert M[4:] not in out and "FAKEFAKE0123" not in out


def test_a_camel_case_name_after_a_newer_prefix_stays():
    assert red("id-xa" + "i-GrokModelConfigLoader") == "id-xa" + "i-GrokModelConfigLoader"


def test_a_real_length_newer_key_after_a_dash_is_redacted():
    out = red("X-Api-Key-" + XAI + " end")
    assert M not in out and out.startswith("X-Api-Key-[REDACTED:secret.xai_key]")


def test_newer_key_before_plus_and_more_text():
    # stricter than the reference: `?q=<key>+more` outside base64 data
    out = red("?q=gs" + "k_" + M + M[:16] + "+more")
    assert M not in out


# --- keyed JSON values ---------------------------------------------------------------------------


def test_keyed_values_in_nested_objects_and_lists():
    out, report = jsonl(
        {
            "credentials": {"user": "FAKEsecretuser1", "nested": ["FAKEsecret2"]},
            "api_key_env": "OPENAI_API_KEY",
            "token_type": "bearer",
            "trackedFileBackups": {"config/secret": {"backupFileName": "abc@v1"}},
        }
    )
    got = json.loads(out)
    assert got["credentials"] == {
        "user": "[REDACTED:secret.keyed_value]",
        "nested": ["[REDACTED:secret.keyed_value]"],
    }
    assert got["api_key_env"] == "OPENAI_API_KEY" and got["token_type"] == "bearer"
    assert got["trackedFileBackups"] == {"config/secret": {"backupFileName": "abc@v1"}}
    assert report.rules == {"secret.keyed_value": 2}


# --- JSONL edge cases ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line,expect",
    [
        ('{"n":1e400,"p":"password=FAKEhunter2"}', '{"n":1e400,"p":"password=[REDACTED:secret.assignment]"}'),
        (
            '{"a":"\\ud800 password=FAKEhunter2"}',
            '{"a":"\\ud800 password=[REDACTED:secret.assignment]"}',
        ),
    ],
)
def test_rewritten_lines_stay_json(line, expect):
    out, _ = jsonl(line + "\n")
    assert out == expect + "\n"
    json.loads(out)


def test_a_repeated_key_under_a_secret_parent_is_judged_against_it():
    out, report = jsonl('{"password":{"v":"FAKEone1","v":"FAKEtwo2"}}\n')
    assert "FAKEone1" not in out and "FAKEtwo2" not in out
    assert report.rules == {"secret.keyed_value": 2}


# --- platform tokens -----------------------------------------------------------------------------

B32 = "abcdefghijklmnopqrstuvwxyz234567" + "abcdefghijklmnopqrst"  # 52 base32 characters


@pytest.mark.parametrize(
    "text,secret,rule",
    [
        ("key " + "to" + "k_FAKEEXAMPLE0000000a1 end", "FAKEEXAMPLE0000000a1", "secret.prefixed_api_token"),
        ("FOO_" + "po" + "l_FAKEEXAMPLE0000000a1", "FAKEEXAMPLE0000000a1", "secret.prefixed_api_token"),
        ("x " + "p" + "t_FAKEEXAMPLE0000000a1", "FAKEEXAMPLE0000000a1", "secret.prefixed_api_token"),
        ("x " + "em" + "it_FAKEEXAMPLE0000000a1", "FAKEEXAMPLE0000000a1", "secret.prefixed_api_token"),
        ("x " + "ge_" + "emit_" + B32, B32, "secret.prefixed_api_token"),
        ("x " + "ge_" + "sess_FAKEEXAMPLE-0000 y", "FAKEEXAMPLE-0000", "secret.a4sx_session"),
    ],
)
def test_platform_tokens(text, secret, rule):
    counts = {}
    out = R.redact_text(text, counts)
    assert secret not in out and rule in counts, (out, counts)


@pytest.mark.parametrize(
    "text",
    [
        "session_" + "tok_3f9aFAKEEXAMPLE000000",
        "on_" + "emit_UserCreated2FA",
        "HASH_" + "tok_abcdef0123456789/x",
    ],
)
def test_platform_token_look_alikes_stay(text):
    assert red(text) == text


# --- CLI mode (the reference client's raw-JSONL pass) --------------------------------------------


@pytest.mark.parametrize(
    "text,secret",
    [
        ("step one\\n--password FAKEpw1 next", "FAKEpw1"),
        ("pwd=FAKEXC:\\Users\\x", "FAKEX"),
        (
            "AK" + "IA" + "FAKEFAKE01234567" + _b64url({"alg": "HS256"}) + "." + _b64url({"s": 1}) + ".sig",
            "FAKEFAKE0123",
        ),
        ("xé10.1.2.3", "10.1.2.3"),
    ],
)
def test_cli_mode_boundaries(text, secret):
    assert secret not in red(text)


def test_cli_mode_can_be_turned_off():
    text = "step one\\n--password FAKEpw1 next"
    assert Redactor(disable=["cli_mode"]).redact_text(text) == text


# --- private keys written as string concatenation (the reference client's private-key pass) -----

KEY_LINES = ["MIIEowIBAAKCAQEA" + "FAKEEXAMPLE" * 4, "NOTAREALKEY" * 5 + "AbCd", "QQQQFAKEEXAMPLE" * 3 + "=="]
CONCAT = {
    "python-implicit": 'k = ("-----BEGIN RSA PRIVATE KEY-----\\n"\n'
    + "".join(f'     "{b}\\n"\n' for b in KEY_LINES)
    + '     "-----END RSA PRIVATE KEY-----\\n")\n',
    "python-plus": 'k = ("-----BEGIN EC PRIVATE KEY-----\\n" + "'
    + KEY_LINES[0]
    + '\\n" + "-----END EC PRIVATE KEY-----")',
    "javascript": 'const k = "-----BEGIN RSA PRIVATE KEY-----\\n" +\n'
    + "".join(f'  "{b}\\n" +\n' for b in KEY_LINES)
    + '  "-----END RSA PRIVATE KEY-----";\n',
    "go": 'k := "-----BEGIN PRIVATE KEY-----\\n" +\n'
    + "".join(f'\t"{b}\\n" +\n' for b in KEY_LINES)
    + '\t"-----END PRIVATE KEY-----"\n',
    "one-line": 'k = "-----BEGIN PRIVATE KEY-----\\n" "'
    + KEY_LINES[0]
    + '\\n" "'
    + KEY_LINES[1]
    + '\\n" "-----END PRIVATE KEY-----"',
}


@pytest.mark.parametrize("form", list(CONCAT))
def test_private_key_as_string_concatenation(form):
    src = CONCAT[form]
    out = red(src)
    assert "FAKEEXAMPLE" not in out and "NOTAREALKEY" not in out, out
    assert out.count("\n") == src.count("\n")  # line breaks kept
    jl, report = jsonl({"c": src})
    assert "FAKEEXAMPLE" not in jl and "NOTAREALKEY" not in jl and "secret.private_key" in report.rules
    tx, _ = redact_bytes(src.encode(), format="text")
    assert b"FAKEEXAMPLE" not in tx and b"NOTAREALKEY" not in tx


def test_concatenated_strings_without_a_key_stay():
    text = 'msg = ("-----BEGIN NOTE-----\\n" "hello world\\n" "-----END NOTE-----")'
    assert red(text) == text


# --- the tail of a key with no BEGIN (text mode too) ---------------------------------------------

TAIL = "$ tail -n 3 key.txt\n" + "\n".join(KEY_LINES) + "\n-----END RSA PRIVATE KEY-----\ndone\n"


def test_key_tail_without_begin_in_text_mode():
    out, report = redact_bytes(TAIL.encode(), format="text")
    assert b"FAKEEXAMPLE" not in out and b"NOTAREALKEY" not in out and out.endswith(b"done\n")
    assert out.count(b"\n") == TAIL.count("\n") and report.rules.get("secret.private_key") == 1
    assert out.decode() == red(TAIL)


@pytest.mark.parametrize("size", [1, 3, 7, 40])
def test_key_tail_streamed_in_chunks_equals_whole_text(size):
    s = StreamRedactor(R)
    out = "".join(s.feed(TAIL[i : i + size]) for i in range(0, len(TAIL), size)) + s.close()
    assert out == R.redact_text(TAIL)


def test_key_tail_in_jsonl():
    out, _ = jsonl({"out": "\n".join(KEY_LINES) + "\n-----END PRIVATE KEY-----"})
    assert "FAKEEXAMPLE" not in out and "NOTAREALKEY" not in out


PUBLIC = {
    "public-key": "-----BEGIN PUBLIC KEY-----\n" + "\n".join(KEY_LINES) + "\n-----END PUBLIC KEY-----\n",
    "rsa-public-key": "-----BEGIN RSA PUBLIC KEY-----\n" + KEY_LINES[0] + "\n-----END RSA PUBLIC KEY-----\n",
    "certificate-tail": "\n".join(KEY_LINES) + "\n-----END CERTIFICATE-----\n",
    "csr-tail": "\n".join(KEY_LINES) + "\n-----END CERTIFICATE REQUEST-----\n",
    "ssh-ed25519": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "FAKEEXAMPLE" * 3 + " fake@example.com\n",
    "marker-in-code": 'if line == "-----END PRIVATE KEY-----":\n    done = True\n',
    "marker-constant": 'END = "-----END PRIVATE KEY-----"\nBEGIN_RE = r"^-----BEGIN"\n',
}


@pytest.mark.parametrize("name", list(PUBLIC))
def test_public_material_and_marker_mentions_stay(name):
    text = PUBLIC[name]
    out, report = redact_bytes(text.encode(), format="text")
    assert out.decode() == text and not report.rules
