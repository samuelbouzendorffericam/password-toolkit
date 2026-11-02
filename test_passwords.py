import unittest

import passcheck
import passgen


class TestPasscheck(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(passcheck.evaluate("azerty123").level, "très faible")
        self.assertEqual(passcheck.evaluate("123456").level, "très faible")

    def test_repeated_characters_are_penalised(self):
        self.assertEqual(passcheck.evaluate("aaaaaaaaaaaa").level, "très faible")

    def test_sequence_is_detected(self):
        self.assertTrue(passcheck.has_run("xxabcdxx"))
        self.assertTrue(passcheck.has_run("4321"))
        self.assertFalse(passcheck.has_run("Tr0ub4dor"))

    def test_sequence_lowers_the_score(self):
        self.assertEqual(passcheck.evaluate("abcdef1234").level, "faible")

    def test_long_random_password_is_very_strong(self):
        result = passcheck.evaluate("k9#Vm2$qLx7!Rt4Z")
        self.assertEqual(result.level, "très fort")
        self.assertEqual(result.problems, [])

    def test_empty_password(self):
        self.assertEqual(passcheck.evaluate("").level, "très faible")


class TestPassgen(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(passgen.generate(20)), 20)

    def test_contains_every_class(self):
        pw = passgen.generate(12)
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(c in passgen.SYMBOLS for c in pw))

    def test_no_ambiguous_characters_by_default(self):
        for _ in range(50):
            self.assertFalse(set(passgen.generate(24)) & passgen.AMBIGUOUS)

    def test_too_short_is_refused(self):
        with self.assertRaises(ValueError):
            passgen.generate(4)

    def test_two_passwords_differ(self):
        self.assertNotEqual(passgen.generate(16), passgen.generate(16))


if __name__ == "__main__":
    unittest.main()
