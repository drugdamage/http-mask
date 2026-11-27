from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mask_http import FragmentError, process_fragment


SCRIPT = Path(__file__).resolve().parents[1] / "mask_http.py"


def request(*headers: str, eol: str = "\n") -> str:
    return eol.join(("GET /sample HTTP/1.1", *headers, "", ""))


def response(*headers: str, eol: str = "\n") -> str:
    return eol.join(("HTTP/1.1 200 OK", *headers, "", ""))


def cli(mode: str, *arguments: str, source: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--mode", mode, *arguments],
        input=source,
        capture_output=True,
        timeout=10,
    )


class HeaderTests(unittest.TestCase):
    def test_basic_scheme_and_field_spelling(self):
        source = request("aUtHoRiZaTiOn: \tBaSiC  ZmFrZTpleGFtcGxl  ")
        self.assertEqual(process_fragment(source, "mask"), request("aUtHoRiZaTiOn: BaSiC MASKED"))

    def test_bearer_token(self):
        source = request("Authorization: Bearer zz-fake~_4.1+/==")
        self.assertEqual(process_fragment(source, "mask"), request("Authorization: Bearer MASKED"))

    def test_unknown_or_malformed_authorization(self):
        for value in ("", "Unknown example", "Basic", "Bearer two tokens", "Basic =bad"):
            with self.subTest(value=value):
                self.assertEqual(
                    process_fragment(request(f"Authorization: {value}", "Host: example.test"), "mask"),
                    request("Host: example.test"),
                )

    def test_cookie_values_empty_and_embedded_equals(self):
        source = request("Cookie: sid=zz-demo==; ui=; SID=zz-example=4")
        expected = request("Cookie: sid=MASKED; ui=; SID=MASKED")
        self.assertEqual(process_fragment(source, "mask"), expected)

    def test_quoted_cookie_values(self):
        source = request('Cookie: sid="zz-quoted=="; empty=""')
        self.assertEqual(process_fragment(source, "mask"), request('Cookie: sid=MASKED; empty=""'))

    def test_bad_cookie_pair_removes_the_whole_field(self):
        for pair in ("broken", "=zz-demo", "two words=zz-demo", 'bad="zz-unclosed', "bad=zz,demo"):
            with self.subTest(pair=pair):
                source = request(f"Cookie: sid=zz-fake; {pair}", "X-Test: stays")
                self.assertEqual(process_fragment(source, "mask"), request("X-Test: stays"))

    def test_set_cookie_attributes_and_expires_comma(self):
        source = response(
            "Set-Cookie: sid=zz-demo; Expires=Wed, 09 Jun 2027 10:18:14 GMT; "
            "Domain=example.test; sEcUrE; Path=/demo; httponly; samesite=lAx; Max-Age=0"
        )
        expected = response("Set-Cookie: sid=MASKED; sEcUrE; httponly; samesite=lAx")
        self.assertEqual(process_fragment(source, "mask"), expected)

    def test_multiples_keep_positions_and_drop_only_the_bad_set_cookie(self):
        source = response(
            "Set-Cookie: sid=zz-first; Secure",
            "X-Order: stable",
            "set-cookie: view=zz-second; Secure=true",
            "Set-Cookie: sid=; HttpOnly; SameSite=None",
            eol="\r\n",
        )
        expected = response(
            "Set-Cookie: sid=MASKED; Secure",
            "X-Order: stable",
            "Set-Cookie: sid=; HttpOnly; SameSite=None",
            eol="\r\n",
        )
        self.assertEqual(process_fragment(source, "mask"), expected)

    def test_flag_with_equals_rejects_set_cookie(self):
        for attribute in ("Secure=", "SECURE=true", "HttpOnly=1"):
            with self.subTest(attribute=attribute):
                source = response(f"Set-Cookie: sid=zz-demo; {attribute}; SameSite=Strict")
                self.assertEqual(process_fragment(source, "mask"), response())

    def test_invalid_samesite(self):
        self.assertEqual(
            process_fragment(response("Set-Cookie: sid=zz-demo; SameSite=Other; Secure"), "mask"),
            response("Set-Cookie: sid=MASKED; Secure"),
        )
        self.assertEqual(
            process_fragment(response("Set-Cookie: sid=zz-demo; SameSite"), "mask"),
            response(),
        )

    def test_remove_all_target_fields_even_if_values_are_malformed(self):
        source = response(
            "Authorization: Whatever zz-demo",
            "X-Test: one",
            "coOkie: no-equals",
            "set-cookie: sid=zz-fake; HttpOnly",
            "x-Test: two",
            "SET-COOKIE: sid=zz-other; Secure=true",
        )
        self.assertEqual(process_fragment(source, "remove"), response("X-Test: one", "x-Test: two"))

    def test_both_modes_leave_start_and_unrelated_fields_unchanged(self):
        for eol in ("\n", "\r\n"):
            with self.subTest(eol=eol):
                text = response("X-Cookie:   original ", "X-Note:\tпроверка", "X-Note: a:b", eol=eol)
                for mode in ("remove", "mask"):
                    self.assertEqual(process_fragment(text, mode), text)

    def test_headerless_blocks_and_per_line_endings(self):
        self.assertEqual(process_fragment(request(eol="\r\n"), "mask"), request(eol="\r\n"))
        mixed = "GET /sample HTTP/1.1\r\nCookie: sid=zz-demo\nX-Test: a\r\n\n"
        self.assertEqual(
            process_fragment(mixed, "mask"),
            "GET /sample HTTP/1.1\r\nCookie: sid=MASKED\nX-Test: a\r\n\n",
        )

    def test_missing_blank_line(self):
        for eol in ("\n", "\r\n"):
            for mode in ("remove", "mask"):
                with self.subTest(eol=eol, mode=mode):
                    with self.assertRaises(FragmentError):
                        process_fragment(request("Cookie: sid=zz-demo", eol=eol)[:-len(eol)], mode)

    def test_folded_header_with_space_or_tab(self):
        for prefix in (" ", "\t"):
            for mode in ("remove", "mask"):
                with self.subTest(prefix=prefix, mode=mode):
                    with self.assertRaisesRegex(FragmentError, "folded header line"):
                        process_fragment(request("Authorization: Bearer zz-demo", prefix + "fold"), mode)

    def test_reject_body_second_message_and_invalid_start_line(self):
        for text in (
            request() + "zz-body",
            request() + request(),
            "GET /sample HTTP/2\n\n",
            request("X-Test: invalid\rcharacter"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(FragmentError):
                    process_fragment(text, "mask")


class CLITests(unittest.TestCase):
    def test_stdin_stdout_preserve_crlf_in_both_modes(self):
        source = request("Cookie: sid=zz-demo", "Host: example.test", eol="\r\n").encode()
        expected = {
            "remove": request("Host: example.test", eol="\r\n").encode(),
            "mask": request("Cookie: sid=MASKED", "Host: example.test", eol="\r\n").encode(),
        }
        for mode, output in expected.items():
            with self.subTest(mode=mode):
                result = cli(mode, source=source)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, output, b""))

    def test_file_options_preserve_non_utf8_header_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.http"
            output = Path(directory) / "result.http"
            source.write_bytes(b"GET /sample HTTP/1.1\r\nX-Note: \xff\r\nCookie: sid=zz-file\r\n\r\n")
            result = cli("mask", "--input", str(source), "--output", str(output))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
            self.assertEqual(output.read_bytes(), b"GET /sample HTTP/1.1\r\nX-Note: \xff\r\nCookie: sid=MASKED\r\n\r\n")

    def test_same_input_and_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.http"
            source.write_bytes(request("Authorization: Bearer zz-demo").encode())
            result = cli("remove", "-i", str(source), "-o", str(source))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
            self.assertEqual(source.read_bytes(), request().encode())

    def test_fragment_errors_have_no_stdout_or_source_content(self):
        cases = (
            (request("Cookie: sid=zz-demo")[:-1], b"mask_http: missing final blank line or unexpected message body\n"),
            (request("Authorization: Bearer zz-demo", "\tzz-fold"), b"mask_http: folded header line\n"),
        )
        for mode in ("mask", "remove"):
            for fragment, error in cases:
                with self.subTest(mode=mode, error=error):
                    result = cli(mode, source=fragment.encode())
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, error)

    def test_invalid_input_neither_overwrites_nor_creates_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing.http"
            missing = Path(directory) / "missing.http"
            existing.write_bytes(b"already here\n")
            for output in (existing, missing):
                with self.subTest(output=output):
                    result = cli("mask", "-o", str(output), source=b"GET /sample HTTP/1.1\n")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
            self.assertEqual(existing.read_bytes(), b"already here\n")
            self.assertFalse(missing.exists())

    def test_missing_input_file_error_is_short(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "absent.http"
            result = cli("mask", "-i", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((result.stdout, result.stderr), (b"", b"mask_http: input or output error\n"))


if __name__ == "__main__":
    unittest.main()
