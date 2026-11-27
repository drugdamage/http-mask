import unittest

from run_experiment import count_secrets, get_marks, observe, percentage


class MeasurementTests(unittest.TestCase):
    def test_one_whole_leak_of_a_repeated_secret_counts_once(self):
        output = "GET /sample HTTP/1.1\nCookie: a=zz-test; b=MASKED\n\n"
        reference = "GET /sample HTTP/1.1\nCookie: a=MASKED; b=MASKED\n\n"
        marks = {("cookie", 1, 1): "zz-test", ("cookie", 1, 2): "zz-test"}
        self.assertEqual(count_secrets(output, observe(output), observe(reference), marks), (1, 0))

    def test_full_and_partial_leaks_in_distinct_cookie_slots(self):
        output = "GET /sample HTTP/1.1\nCookie: a=zz-test; b=MASKED-est\n\n"
        reference = "GET /sample HTTP/1.1\nCookie: a=MASKED; b=MASKED\n\n"
        marks = {("cookie", 1, 1): "zz-test", ("cookie", 1, 2): "zz-test"}
        self.assertEqual(count_secrets(output, observe(output), observe(reference), marks), (1, 1))

    def test_whole_leak_found_outside_target_header(self):
        output = "GET /sample HTTP/1.1\nX-Note: zz-relocated-example\n\n"
        reference = "GET /sample HTTP/1.1\n\n"
        marks = {("authorization", 1, 1): "zz-relocated-example"}
        self.assertEqual(count_secrets(output, observe(output), observe(reference), marks), (1, 0))

    def test_partial_leak_is_found_when_changed_value_is_a_substring_of_marker(self):
        output = "GET /sample HTTP/1.1\nAuthorization: Bearer AS\n\n"
        reference = "GET /sample HTTP/1.1\nAuthorization: Bearer MASKED\n\n"
        marks = {("authorization", 1, 1): "fictionalASexample"}
        self.assertEqual(count_secrets(output, observe(output), observe(reference), marks), (0, 1))

    def test_elements_from_another_field_occurrence_do_not_count(self):
        marks = {
            "annotations": [
                {"header": "Set-Cookie", "occurrence": 1, "secrets": [], "cookie_names": ["sid"],
                 "attributes": ["Secure", "SameSite=Lax"]},
                {"header": "Set-Cookie", "occurrence": 2, "secrets": [], "cookie_names": ["sid"],
                 "attributes": ["HttpOnly"]},
            ]
        }
        output = observe(
            "HTTP/1.1 200 OK\nSet-Cookie: view=MASKED; SameSite=Strict\n"
            "set-cookie: sid=MASKED; secure; HttpOnly\n\n"
        )
        _, elements = get_marks(marks)
        self.assertEqual(sum((elements & output.elements).values()), 2)

    def test_zero_denominator_and_percentage(self):
        self.assertIsNone(percentage(0, 0))
        self.assertEqual(percentage(1, 3), 33.33)


if __name__ == "__main__":
    unittest.main()
