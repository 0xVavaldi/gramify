"""Tests for gramify.py. Run with: python -m unittest discover -s tests"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "gramify.py")
sys.path.insert(0, ROOT)

import gramify  # noqa: E402


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def write_input(self, data, name="in.txt"):
        if isinstance(data, str):
            data = data.encode("utf-8")
        with open(os.path.join(self.dir, name), "wb") as f:
            f.write(data)
        return name

    def run_gramify(self, *args, stdin=None, expect_ok=True, timeout=30):
        result = subprocess.run([sys.executable, SCRIPT] + list(args), cwd=self.dir, input=stdin,
                                capture_output=True, timeout=timeout)
        if expect_ok:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def read_bytes(self, name):
        with open(os.path.join(self.dir, name), "rb") as f:
            return f.read()

    def read_lines(self, name):
        data = self.read_bytes(name).decode("utf-8", "surrogateescape")
        return data.split("\n")[:-1] if data else []


class KGramTests(unittest.TestCase):
    def test_split_matches_help_text(self):
        start, mid, end = gramify.kgrams_split("password12", 3, 8)
        self.assertEqual(start, ["pas", "pass", "passw", "passwo", "passwor", "password"])
        self.assertEqual(mid, ["password", "assword1", "ssword12"])
        self.assertEqual(end, ["ssword12", "sword12", "word12", "ord12", "rd12", "d12"])

    def test_split_never_contains_whole_word(self):
        start, mid, end = gramify.kgrams_split("password", 3, 8)
        self.assertNotIn("password", start + mid + end)
        self.assertEqual(gramify.kgrams_split("abc", 3, 8), ([], [], []))

    def test_split_handles_long_lines(self):
        # Used to be skipped (> 256 characters) because of the recursive implementation
        word = "a" * 5000
        start, mid, end = gramify.kgrams_split(word, 3, 8)
        self.assertEqual(len(start), 6)
        self.assertEqual(len(mid), 5000 - 8 + 1)

    def test_rolling(self):
        self.assertEqual(gramify.kgrams_rolling("faltu1", 3, 4),
                         ["fal", "alt", "ltu", "tu1", "falt", "altu", "ltu1"])
        self.assertEqual(gramify.kgrams_rolling("ab", 3, 8), [])


class CGramTests(unittest.TestCase):
    def runs(self, text, classes=gramify.STRICT_CLASSES):
        return gramify.split_charset_runs(text, classes)

    def test_case_boundaries(self):
        self.assertEqual(self.runs("PASSword123123magicman"), ["PASS", "word", "123123", "magicman"])
        self.assertEqual(self.runs("PassWord123456"), ["Pass", "Word", "123456"])

    def test_capital_after_short_run(self):
        # "1Password" used to give "assword" because the "1" run was too short to keep
        self.assertEqual(self.runs("1Password"), ["1", "Password"])
        self.assertEqual(self.runs("123Password"), ["123", "Password"])

    def test_colon_and_equals_are_special(self):
        self.assertEqual(self.runs("Pass:word=123"), ["Pass", ":", "word", "=", "123"])
        self.assertEqual(self.runs("ab:cd", gramify.MIXED_CLASSES), ["ab", ":", "cd"])

    def test_unknown_characters_join_the_run(self):
        self.assertEqual(self.runs("caféteria"), ["caféteria"])

    def test_mixed_passes(self):
        self.assertEqual(self.runs("PaSSwOrd123123", gramify.MIXED_CLASSES), ["PaSSwOrd", "123123"])
        self.assertEqual(self.runs("PaSS123!x", gramify.MIXED_NUMERIC_CLASSES), ["PaSS123", "!", "x"])

    def test_filter_parsing(self):
        self.assertEqual(gramify.parse_filter("startmidend"), ["start", "mid", "end"])
        self.assertEqual(gramify.parse_filter("duo"), "duo")
        for bad in ("Start", "starts", "middle", "begin"):
            with self.assertRaises(gramify.UsageError):
                gramify.parse_filter(bad)

    def test_filter_combinations(self):
        items = [item for item, _ in gramify.build_filters(None, 2)]
        self.assertEqual(items, ["start", "mid", "end", "startmid", "startend", "midstart", "midend", "endstart", "endmid"])
        items = [item for item, _ in gramify.build_filters("start,mid", 1)]
        self.assertEqual(items, ["start", "mid", "end"])  # duplicates removed

    def test_rule_encoding(self):
        self.assertEqual(gramify.prepend_rule("ab"), "^b ^a")
        self.assertEqual(gramify.append_rule("a b\\"), "$a $\\x20 $b $\\x5c")
        # é is two bytes in UTF-8; prepending must reverse the bytes, not the character
        self.assertEqual(gramify.prepend_rule("é"), "^\\xa9 ^\\xc3")
        self.assertEqual(gramify.insert_rules(["xy", "z"], 2), ["i2y i2x", "i4z"])
        self.assertEqual(gramify.overwrite_rules(["xy", "z"], 2), ["o2x o3y", "o4z"])

    def test_rules_beyond_position_z_are_not_built(self):
        # hashcat positions stop at Z (35); a partial mid would build a different word
        self.assertIsNone(gramify.insert_rules(["abc"], 36))
        self.assertIsNone(gramify.overwrite_rules(["abc"], 34))
        self.assertEqual(gramify.overwrite_rules(["ab"], 34), ["oYa oZb"])

    def test_rule_limits(self):
        self.assertTrue(gramify.is_valid_rule(" ".join(["$a"] * 31)))
        self.assertFalse(gramify.is_valid_rule(" ".join(["$a"] * 32)))


class NGramTests(CliTestCase):
    def test_does_not_cross_lines_with_per_line(self):
        self.write_input("correct horse\nbattery staple\n")
        self.run_gramify("word", "in.txt", "o.txt", "--max-length=2", "--per-line", "--quiet")
        lines = self.read_lines("n_o.txt")
        self.assertNotIn("horse battery", lines)
        self.assertIn("correct horse", lines)

    def test_running_text_crosses_lines_by_default(self):
        self.write_input("correct horse\nbattery staple\n")
        self.run_gramify("word", "in.txt", "o.txt", "--max-length=2", "--quiet")
        self.assertIn("horse battery", self.read_lines("n_o.txt"))

    def test_ngram_more_skips_words_without_letters_or_digits(self):
        self.write_input("hello !!! World\n")
        self.run_gramify("word", "in.txt", "o.txt", "--min-length=2", "--max-length=2", "--ngram-more", "--quiet")
        lines = self.read_lines("n_o.txt")
        self.assertIn("hello World", lines)
        self.assertIn("hello world", lines)
        self.assertFalse(any("  " in line or line != line.strip() for line in lines), lines)

    def test_ngram_more_in_stdout_mode(self):
        self.write_input("It's me\n")
        result = self.run_gramify("word", "in.txt", "--stdout", "--ngram-more", "--quiet")
        self.assertEqual(sorted(result.stdout.decode().split("\n")[:-1]),
                         sorted(["It's", "me", "It's me", "Its", "me", "Its me", "its", "me", "its me"]))


class CliTests(CliTestCase):
    def test_filter_typo_is_an_error_not_a_hang(self):
        self.write_input("Pass!word123\n")
        result = self.run_gramify("charset", "in.txt", "o.txt", "--filter=Start", expect_ok=False, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"not a valid filter", result.stderr)

    def test_filter_combo_length_creates_files(self):
        self.write_input("Pass!word123\n")
        self.run_gramify("charset", "in.txt", "o.txt", "--filter-combo-length=2", "--min-length=1", "--quiet")
        # [Pass, !, word, 123]; the glued pass gives [Pass!word, 123], which is a duo
        self.assertEqual(self.read_lines("c_startmid_o.txt"), ["Pass!word"])
        self.assertEqual(self.read_lines("c_end_o.txt"), ["123"])
        self.assertEqual(self.read_lines("c_midstart_o.txt"), ["!wordPass"])

    def test_filters(self):
        self.write_input("PASSword123123magicman\npassword123456\npassword\n")
        self.run_gramify("charset", "in.txt", "o.txt", "--filter=solo,duo,start,mid,end,startmid,midend", "--quiet")
        self.assertEqual(self.read_lines("c_start_o.txt"), ["PASS"])
        self.assertEqual(self.read_lines("c_mid_o.txt"), ["word123123"])
        self.assertEqual(self.read_lines("c_end_o.txt"), ["magicman"])
        self.assertEqual(self.read_lines("c_startmid_o.txt"), ["PASSword123123"])
        self.assertEqual(self.read_lines("c_midend_o.txt"), ["word123123magicman"])
        self.assertEqual(self.read_lines("c_duo_o.txt"), ["password123456"])
        self.assertEqual(self.read_lines("c_solo_o.txt"), ["password"])

    def test_rulify(self):
        self.write_input("ab!cd!ef\n")
        self.run_gramify("charset", "in.txt", "o.txt", "--min-length=1", "--filter=startmidend", "--cgram-rulify-beta", "--quiet")
        self.assertEqual(self.read_lines("c_startmidend_o.txt.rule"), [
            "^b ^a i2! i3d i3c i5! $e $f",
            "^b ^a o2! o3c o4d o5! $e $f",
            # glued pass: [ab!cd, !, ef]
            "^d ^c ^! ^b ^a i5! $e $f",
            "^d ^c ^! ^b ^a o5! $e $f",
        ])

    def test_rulify_skips_incomplete_mid_rules(self):
        self.write_input("a" * 40 + "123bcd!!\n")
        result = self.run_gramify("charset", "in.txt", "o.txt", "--min-length=1", "--max-length=40",
                                  "--filter=midend,mid", "--cgram-rulify-beta")
        self.assertEqual(self.read_lines("c_midend_o.txt.rule"), [])
        self.assertEqual(self.read_lines("c_mid_o.txt.rule"), [])
        self.assertEqual(self.read_lines("c_midend_o.txt"), ["123bcd!!"])
        self.assertIn(b"Skipped", result.stderr)

    def test_rulify_keeps_start_end_rules_when_mids_do_not_fit(self):
        self.write_input("abc" + "1" * 35 + "!xyz\n")
        self.run_gramify("charset", "in.txt", "o.txt", "--min-length=1", "--max-length=40",
                         "--filter=startend,start,end,mid", "--cgram-rulify-beta", "--quiet")
        self.assertEqual(self.read_lines("c_start_o.txt.rule"), ["^c ^b ^a"])
        self.assertEqual(self.read_lines("c_end_o.txt.rule"), ["$x $y $z"])
        self.assertEqual(self.read_lines("c_startend_o.txt.rule"), ["^c ^b ^a $x $y $z"])
        self.assertEqual(self.read_lines("c_mid_o.txt.rule"), [])

    def test_output_cannot_overwrite_input(self):
        self.write_input("hello world foo\n", name="n_x.txt")
        result = self.run_gramify("word", "n_x.txt", "x.txt", expect_ok=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.read_bytes("n_x.txt"), b"hello world foo\n")
        with open(os.path.join(self.dir, "n_x.txt"), "rb") as stdin:
            result = subprocess.run([sys.executable, SCRIPT, "word", "-", "x.txt"], cwd=self.dir, stdin=stdin,
                                    capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.read_bytes("n_x.txt"), b"hello world foo\n")

    def test_hex_with_whitespace_is_literal(self):
        self.write_input("$HEX[41 42]\n")
        result = self.run_gramify("character", "in.txt", "--stdout", "--rolling", "--min-length=11", "--quiet")
        self.assertEqual(result.stdout, b"$HEX[244845585b34312034325d]\n")

    def test_hex_input_is_decoded(self):
        self.write_input("$HEX[70617373776f7264]\n$HEX[zz]\n")
        self.run_gramify("character", "in.txt", "o.txt", "--rolling", "--min-length=8", "--quiet")
        # $HEX[zz] is not valid hex, so it is used as-is (like hashcat does). A gram that starts
        # with $HEX[ is itself written in hex so hashcat does not try to decode it.
        self.assertEqual(self.read_lines("k_rolling.o.txt"), ["password", "$HEX[244845585b7a7a5d]"])

    def test_hex_output_for_control_characters(self):
        self.write_input("$HEX[6162630a646566]\n")  # "abc\ndef"
        self.run_gramify("character", "in.txt", "o.txt", "--rolling", "--min-length=4", "--max-length=4", "--quiet")
        self.assertEqual(self.read_lines("k_rolling.o.txt"),
                         ["$HEX[6162630a]", "$HEX[62630a64]", "$HEX[630a6465]", "$HEX[0a646566]"])

    def test_invalid_utf8_is_kept_byte_for_byte(self):
        self.write_input(b"pass\xe9word\n")  # latin-1 é
        self.run_gramify("character", "in.txt", "o.txt", "--rolling", "--min-length=9", "--quiet")
        self.assertEqual(self.read_bytes("k_rolling.o.txt"), b"pass\xe9word\n")

    def test_overwrites_by_default_and_appends_on_request(self):
        self.write_input("abcd\n")
        args = ["character", "in.txt", "o.txt", "--rolling", "--min-length=4", "--quiet"]
        self.run_gramify(*args)
        self.run_gramify(*args)
        self.assertEqual(self.read_lines("k_rolling.o.txt"), ["abcd"])
        self.run_gramify(*args, "--append")
        self.assertEqual(self.read_lines("k_rolling.o.txt"), ["abcd", "abcd"])

    def test_count_and_min_count(self):
        self.write_input("abc\nabc\nabd\nabc\n")
        self.run_gramify("character", "in.txt", "o.txt", "--rolling", "--min-length=2", "--max-length=3", "--count", "--quiet")
        # most common first; ties keep the order they were first seen in
        self.assertEqual(self.read_lines("k_rolling.o.txt"), ["ab", "bc", "abc", "bd", "abd"])
        self.run_gramify("character", "in.txt", "o.txt", "--rolling", "--min-length=2", "--max-length=3", "--min-count=3", "--quiet")
        self.assertEqual(self.read_lines("k_rolling.o.txt"), ["ab", "bc", "abc"])

    def test_output_prefix_goes_on_the_file_name(self):
        os.mkdir(os.path.join(self.dir, "out"))
        self.write_input("abcdef\n")
        self.run_gramify("character", "in.txt", os.path.join("out", "list.txt"), "--quiet")
        for prefix in ("k_start.", "k_mid.", "k_end."):
            self.assertTrue(os.path.isfile(os.path.join(self.dir, "out", prefix + "list.txt")))

    def test_stdin_and_stdout(self):
        result = self.run_gramify("character", "-", "--stdout", "--rolling", "--min-length=3", "--max-length=3",
                                  stdin=b"abcd\r\n")
        self.assertEqual(result.stdout, b"abc\nbcd\n")
        self.assertNotIn(b"Writing", result.stdout)

    def test_stdout_for_charset(self):
        result = self.run_gramify("charset", "-", "--stdout", "--quiet", stdin=b"Pass!word123\n")
        self.assertEqual(result.stdout.split(b"\n")[:3], [b"Pass", b"word", b"123"])

    def test_invalid_option_combinations(self):
        self.write_input("abc\n")
        for args in (["character", "in.txt", "--stdout"],
                     ["charset", "in.txt", "--stdout", "--filter=start"],
                     ["charset", "in.txt", "o.txt", "--cgram-rulify-beta"],
                     ["character", "in.txt", "o.txt", "--min-length=10"],
                     ["character", "in.txt", "o.txt", "--min-length=0"],
                     ["character", "in.txt", "o.txt", "--min-length=abc"],
                     ["character", "in.txt", "o.txt", "--count", "--append"],
                     ["character", "missing.txt", "o.txt"]):
            result = self.run_gramify(*args, expect_ok=False)
            self.assertEqual(result.returncode, 1, args)

    def test_help_parses_every_option(self):
        from docopt import parse_defaults
        options = sorted(option.long for option in parse_defaults(gramify.__doc__))
        self.assertEqual(options, sorted([
            "--min-length", "--max-length", "--stdout", "--count", "--min-count", "--append", "--quiet", "--help",
            "--version", "--ngram-more", "--per-line", "--rolling", "--mixed", "--filter", "--filter-combo-length",
            "--cgram-rulify-beta"]))
        result = self.run_gramify("--help")
        self.assertIn(b"Examples:", result.stdout)

    def test_missing_stdin(self):
        result = subprocess.run([sys.executable, SCRIPT, "word", "-", "--stdout"], cwd=self.dir,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)  # an empty STDIN is fine
        result = subprocess.run([sys.executable, "-c", "import os, runpy, sys; os.close(0); sys.stdin = None; "
                                 "sys.argv = ['gramify.py', 'word', '-', '--stdout']; "
                                 "runpy.run_path(%r, run_name='__main__')" % SCRIPT],
                                cwd=self.dir, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"STDIN is not available", result.stderr)

    def run_without(self, stream, *args):
        """Runs gramify with sys.stdin or sys.stderr set to None, like pythonw or a closed descriptor."""
        code = ("import runpy, sys; sys.%s = None; sys.argv = ['gramify.py'] + %r; "
                "runpy.run_path(%r, run_name='__main__')" % (stream, list(args), SCRIPT))
        return subprocess.run([sys.executable, "-c", code], cwd=self.dir, capture_output=True, timeout=30)

    def test_file_input_without_stdin(self):
        self.write_input("abcd\n")
        result = self.run_without("stdin", "character", "in.txt", "o.txt", "--rolling", "--min-length=4")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.read_lines("k_rolling.o.txt"), ["abcd"])

    def test_no_stderr_keeps_stdout_clean(self):
        self.write_input("abcd\n")
        result = self.run_without("stderr", "character", "in.txt", "--stdout", "--rolling", "--min-length=4")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.replace(b"\r\n", b"\n"), b"abcd\n")
        result = self.run_without("stderr", "character", "missing.txt", "--stdout", "--rolling")
        self.assertEqual((result.returncode, result.stdout), (1, b""))

    def test_refused_overwrite_touches_no_file(self):
        self.write_input("keep me\n", name="k_start.kk")
        self.write_input("abcdefghij\n", name="k_mid.kk")
        result = self.run_gramify("character", "k_mid.kk", "kk", expect_ok=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.read_bytes("k_start.kk"), b"keep me\n")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "k_end.kk")))

    def test_unwritable_output_is_a_message(self):
        self.write_input("abcd\n")
        for output in (os.path.join("missing_dir", "o.txt"), "out" + os.sep):
            result = self.run_gramify("word", "in.txt", output, expect_ok=False)
            self.assertEqual(result.returncode, 1, output)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_no_crlf_on_windows(self):
        self.write_input("abcd\n")
        self.run_gramify("character", "in.txt", "o.txt", "--rolling", "--min-length=4", "--quiet")
        self.assertEqual(self.read_bytes("k_rolling.o.txt"), b"abcd\n")


if __name__ == "__main__":
    unittest.main()
