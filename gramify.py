#!/usr/bin/env python3
"""gramify - n-gram generator on word, character and charset basis

Splits every line of a wordlist or text into words (n-grams), characters (k-grams) or charset
parts (c-grams), to build wordlists, rules and hybrid-attack input from cracked passwords,
quotes or lyrics.

Usage:
  gramify.py word <input_file> (<output_file> | --stdout) [--min-length=<int>] [--max-length=<int>] [--ngram-more] [--per-line] [--count] [--min-count=<int>] [--append] [--quiet]
  gramify.py character <input_file> (<output_file> | --stdout) [--min-length=<int>] [--max-length=<int>] [--rolling] [--count] [--min-count=<int>] [--append] [--quiet]
  gramify.py charset <input_file> (<output_file> | --stdout) [--min-length=<int>] [--max-length=<int>] [--mixed] [--filter=<str>] [--filter-combo-length=<int>] [--cgram-rulify-beta] [--count] [--min-count=<int>] [--append] [--quiet]
  gramify.py (-h | --help)
  gramify.py --version

Arguments:
  <input_file>                  File to read, one entry per line. Use - to read from STDIN.
                                Lines in $HEX[...] notation are decoded first.
  <output_file>                 Base name for the output files. Each mode adds a prefix to the file
                                name (see Output files), so out/list.txt becomes out/n_list.txt.

Common options:
  --min-length=<int>            Shortest gram: in words for word mode, in characters otherwise.
                                Defaults: word 1, character 3, charset 3.
  --max-length=<int>            Longest gram. Defaults: word 10, character 8 (32 with rolling),
                                charset 32.
  --stdout                      Print to STDOUT instead of writing files. Not possible when a mode
                                writes several files: character without rolling, charset with filters.
  --count                       De-duplicate in memory and sort each output by frequency, most
                                common first. Needs enough RAM to hold every unique gram.
  --min-count=<int>             Drop grams seen fewer than <int> times. Implies --count.
  --append                      Add to existing output files. By default they are overwritten.
                                Cannot be combined with --count.
  --quiet                       No progress bar or status messages (these go to STDERR).
  -h --help                     Show this screen.
  --version                     Show version.

Word options:
  --ngram-more                  Also output each n-gram with special characters removed from the
                                words, plus a lowercase copy of that.
  --per-line                    Do not build n-grams across line boundaries. Use it for passphrase
                                lists; leave it off for running text such as books or lyrics.

Character options:
  --rolling                     Write every substring to one file instead of separate start, mid
                                and end files.

Charset options:
  --mixed                       Two extra passes: one that keeps upper and lowercase together, and
                                one that also keeps digits with the letters. In these passes the
                                characters ' and - do not split parts either.
  --filter=<str>                Comma separated filters, see Filters below. Each filter is written
                                to c_<filter>_<output_file>.
  --filter-combo-length=<int>   [BETA] Add every combination of start, mid and end of up to <int>
                                parts as a filter. Repeats such as startstart are skipped.
  --cgram-rulify-beta           [BETA] Also write each filter as hashcat rules, to
                                c_<filter>_<output_file>.rule. Rules that do not fit hashcat's limits
                                (31 functions, 255 characters, positions up to Z) are skipped.

Output files:
  word                          n_<output_file>: every run of min-length to max-length words.
  character                     k_start.<output_file>: prefixes of min-length to max-length characters.
                                k_mid.<output_file>: every substring of exactly max-length characters
                                (only for lines longer than max-length).
                                k_end.<output_file>: suffixes of min-length to max-length characters.
                                Prefixes and suffixes never contain the whole line, and lines of
                                min-length characters or fewer produce nothing.
  character with rolling        k_rolling.<output_file>: every substring of min-length to max-length.
  charset                       c_<output_file>, plus c_<filter>_<output_file> per filter and, with
                                rulify, c_<filter>_<output_file>.rule.
  Without --count the output contains duplicates. Grams with control characters (or starting
  with $HEX[) are written in $HEX[...] notation.

Filters:
  A password split into parts [first, ..., last] has a start (first part), mid (all parts in
  between, joined) and end (last part). Combine them in any order: startmid, midend, startend, ...
  These position filters only match passwords with 3 or more parts; use the duo filters for 2.
  solo                          passwords with exactly 1 part.
  duo, duostart, duoend         passwords with exactly 2 parts: both, the first, the second.
  start, mid, end               the first part, the middle parts, the last part.
  startmid                      everything but the last part, perfect for hashcat -a6.
  midend                        everything but the first part, perfect for hashcat -a7.
  Parts are the cgrams that pass the length limits, so use --min-length=1 when filtering on mid.

Gram-types:
  K-Gram (Character):           Letter based https://nlp.stanford.edu/IR-book/html/htmledition/k-gram-indexes-for-wildcard-queries-1.html
  N-Gram (Word):                Word based https://en.wikipedia.org/wiki/N-gram
  C-Gram (Charset):             Charset boundary inspired by https://github.com/hops/pack2/blob/master/src/cgrams.rs

Examples:
  gramify.py character found.txt grams.txt --rolling --min-count=5
  gramify.py charset found.txt parts.txt --min-length=1 --filter=start,mid,end,startmid,midend
  gramify.py word lyrics.txt phrases.txt --max-length=6 --count
  cat found.txt | gramify.py character - --stdout --rolling | sort | uniq -c | sort -rn
"""
import errno
import os
import re
import sys
from collections import Counter
from itertools import product

from docopt import docopt

VERSION = "2.5"

# Hashcat rule limits (include/rp.h): positions are 0-9A-Z, a rule holds at most
# 31 functions (RULES_MAX - 1) and 255 characters (RP_RULE_SIZE - 1).
RULE_POSITIONS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
RULE_MAX_FUNCTIONS = 31
RULE_MAX_LENGTH = 255

LOWERCASE = frozenset("abcdefghijklmnopqrstuvwxyz")
UPPERCASE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
NUMERIC = frozenset("0123456789")
# does not include ' and - because of their common use in normal language
SPECIAL = frozenset("!\"#$%&()*+,./:;<=>?@[\\]^_`{|}~ ")
SPECIAL_FULL = SPECIAL | frozenset("'-")

UNKNOWN = "unknown"  # characters outside every set join whatever run they are in
LOWER = "lowercase"
UPPER = "uppercase"
WORD_START = "wordstart"  # first letter of a run; the next letter decides upper or lower

STRICT_CLASSES = {}
STRICT_CLASSES.update(dict.fromkeys(LOWERCASE, LOWER))
STRICT_CLASSES.update(dict.fromkeys(UPPERCASE, UPPER))
STRICT_CLASSES.update(dict.fromkeys(NUMERIC, "numeric"))
STRICT_CLASSES.update(dict.fromkeys(SPECIAL_FULL, "special"))  # use special full on the most strict pass

MIXED_CLASSES = {}
MIXED_CLASSES.update(dict.fromkeys(LOWERCASE | UPPERCASE, "mixedcase"))
MIXED_CLASSES.update(dict.fromkeys(NUMERIC, "numeric"))
MIXED_CLASSES.update(dict.fromkeys(SPECIAL, "special"))

MIXED_NUMERIC_CLASSES = {}
MIXED_NUMERIC_CLASSES.update(dict.fromkeys(LOWERCASE | UPPERCASE | NUMERIC, "mixedcasenumeric"))
MIXED_NUMERIC_CLASSES.update(dict.fromkeys(SPECIAL, "special"))

SHAPE_FILTERS = ("solo", "duo", "duostart", "duoend")
POSITION_TOKENS = ("start", "mid", "end")

_NEEDS_HEX = re.compile(r"[\x00-\x1f\x7f]")
_HEX_DIGITS = re.compile(rb"(?:[0-9a-fA-F]{2})*")


class UsageError(Exception):
    pass


def info(message):
    if not QUIET:
        print(message, file=sys.stderr)


def error_message(message):
    # With no STDERR at all, print() would fall back to STDOUT and end up between the grams
    if sys.stderr is not None:
        print(message, file=sys.stderr)


def needs_hex(text):
    return text.startswith("$HEX[") or _NEEDS_HEX.search(text) is not None


def line_is_clean(line):
    """True when no substring of line needs $HEX[] notation."""
    return "$HEX[" not in line and _NEEDS_HEX.search(line) is None


def to_output(gram):
    if needs_hex(gram):
        return "$HEX[" + gram.encode("utf-8", "surrogateescape").hex() + "]"
    return gram


def decode_line(raw):
    line = raw.rstrip(b"\r\n")
    # Anything that is not valid hex is used as-is, like hashcat does
    if line.startswith(b"$HEX[") and line.endswith(b"]") and _HEX_DIGITS.fullmatch(line, 5, len(line) - 1):
        line = bytes.fromhex(line[5:-1].decode("ascii"))
    # surrogateescape keeps bytes that are not valid UTF-8 so they are written back unchanged
    return line.decode("utf-8", "surrogateescape")


def read_lines(input_file):
    is_stdin = input_file == "-"
    if is_stdin:
        handle, total = sys.stdin.buffer, None
    else:
        # Pipes such as <(zcat list.gz) have no size, so the progress bar gets no total
        handle = open(input_file, "rb")
        total = os.path.getsize(input_file) if os.path.isfile(input_file) else None

    bar = None
    if not QUIET:
        try:
            from tqdm import tqdm  # optional, and slow to import, so only loaded when shown
            bar = tqdm(total=total, unit="B", unit_scale=True, unit_divisor=1024, file=sys.stderr,
                       bar_format="{l_bar}{bar:50}{r_bar}{bar:-50b}")
        except ImportError:
            pass
    pending = 0
    try:
        for raw in handle:
            if bar is not None:
                pending += len(raw)
                if pending >= 1 << 20:
                    bar.update(pending)
                    pending = 0
            yield decode_line(raw)
    finally:
        if bar is not None:
            bar.update(pending)
            bar.close()
        if not is_stdin:
            handle.close()


class GramWriter:
    """Writes grams to a file or STDOUT, or counts them when --count is used."""

    def __init__(self, path, settings, buffer_size):
        self.path = path
        self.min_count = settings["min_count"]
        self.counter = Counter() if settings["count"] else None
        if path is None:
            self.handle = sys.stdout.buffer
        else:
            self.handle = open(path, "ab" if settings["append"] else "wb", buffering=buffer_size)

    def add(self, grams, clean=False):
        """clean=True promises that no gram needs $HEX[] notation."""
        if not grams:
            return
        if self.counter is not None:
            self.counter.update(grams)
            return
        if not clean:
            grams = [to_output(gram) for gram in grams]
        self._write(grams)

    def _write(self, grams):
        try:
            self.handle.write(("\n".join(grams) + "\n").encode("utf-8", "surrogateescape"))
        except OSError as error:
            # Windows reports a closed pipe (e.g. "| head") as EINVAL instead of EPIPE
            if self.path is None and error.errno == errno.EINVAL:
                raise BrokenPipeError(errno.EPIPE, "Broken pipe") from None
            raise

    def close(self):
        if self.counter is not None:
            grams = [to_output(gram) for gram, count in self.counter.most_common() if count >= self.min_count]
            self.counter = None
            if grams:
                self._write(grams)
        if self.path is not None:
            self.handle.close()
            return
        try:
            self.handle.flush()
        except OSError as error:
            if error.errno == errno.EINVAL:
                raise BrokenPipeError(errno.EPIPE, "Broken pipe") from None
            raise


def output_path(output_file, prefix):
    """Prefix the file name, not the directory: out/list.txt -> out/<prefix>list.txt"""
    directory, name = os.path.split(output_file)
    return os.path.join(directory, prefix + name)


def planned_outputs(settings):
    """Every file this run writes, so they can be checked before any of them is opened."""
    output_file = settings["output_file"]
    if output_file is None:
        return []
    if settings["mode"] == "word":
        prefixes = ["n_"]
    elif settings["mode"] == "character":
        prefixes = ["k_rolling."] if settings["rolling"] else ["k_start.", "k_mid.", "k_end."]
    else:
        prefixes = ["c_"] + ["c_" + item + "_" for item, _ in settings["filters"]]
    paths = [output_path(output_file, prefix) for prefix in prefixes]
    if settings["rulify"]:
        paths += [output_path(output_file + ".rule", "c_" + item + "_") for item, _ in settings["filters"]]
    return paths


def check_outputs(settings):
    if settings["output_file"] is not None and not os.path.basename(settings["output_file"]):
        raise UsageError("<output_file> should be a file name, not a directory: " + settings["output_file"])
    for path in planned_outputs(settings):
        if not os.path.exists(path):
            continue
        if settings["input_file"] == "-":
            same = sys.stdin is not None and os.path.samestat(os.fstat(sys.stdin.fileno()), os.stat(path))
        else:
            same = os.path.samefile(path, settings["input_file"])
        if same:
            raise UsageError("Output file " + path + " is the input file; choose another <output_file>.")


def open_writer(settings, prefix, buffer_size=1 << 20):
    """Filter outputs can open thousands of files, so they ask for a smaller buffer."""
    if settings["output_file"] is None:
        return GramWriter(None, settings, buffer_size)
    path = output_path(settings["output_file"], prefix)
    try:
        writer = GramWriter(path, settings, buffer_size)
    except OSError as error:
        raise UsageError("Cannot write " + path + ": " + (error.strerror or str(error)))
    info("Writing output to: " + path)
    settings["written_files"].append(path)
    return writer


##############
### N-gram ###
##############

def alphanum_string(stringx):
    return "".join(character for character in stringx if character.isalnum())


def push_word(window, word, max_length):
    window.append(word)
    if len(window) > max_length:
        del window[0]


def ngrams_ending_at_newest(window, min_length):
    size = len(window)
    return [" ".join(window[size - n:]) for n in range(min_length, size + 1)]


def ngramify(settings):
    min_length, max_length = settings["min_length"], settings["max_length"]
    ngram_more = settings["ngram_more"]
    per_line = settings["per_line"]
    out = open_writer(settings, "n_")

    # Stream through the words with a sliding window instead of loading the whole file
    words = []
    alnum_words = []
    try:
        for line in read_lines(settings["input_file"]):
            if per_line:
                words.clear()
                alnum_words.clear()
            grams = []
            for word in line.split(" "):
                if not word:
                    continue
                push_word(words, word, max_length)
                grams += ngrams_ending_at_newest(words, min_length)
                if ngram_more:
                    alnum_word = alphanum_string(word)
                    if not alnum_word:
                        continue
                    push_word(alnum_words, alnum_word, max_length)
                    alnum_grams = ngrams_ending_at_newest(alnum_words, min_length)
                    grams += alnum_grams
                    grams += [gram.lower() for gram in alnum_grams]
            out.add(grams)
    finally:
        out.close()


##############
### K-gram ###
##############

def kgrams_rolling(word, min_length, max_length):
    word_length = len(word)
    return [word[j:j + i]
            for i in range(min_length, min(max_length, word_length) + 1)
            for j in range(word_length - i + 1)]


def kgrams_split(word, min_length, max_length):
    """Returns (start, mid, end) k-grams; see "Output files" in the help text."""
    word_length = len(word)
    if word_length <= min_length:
        return [], [], []
    longest = min(max_length, word_length - 1)
    start = [word[:i] for i in range(min_length, longest + 1)]
    mid = [word[j:j + max_length] for j in range(word_length - max_length + 1)] if word_length > max_length else []
    end = [word[word_length - i:] for i in range(longest, min_length - 1, -1)]
    return start, mid, end


def kgramify(settings):
    min_length, max_length = settings["min_length"], settings["max_length"]
    lines = read_lines(settings["input_file"])

    if settings["rolling"]:
        out = open_writer(settings, "k_rolling.")
        try:
            for line in lines:
                out.add(kgrams_rolling(line, min_length, max_length), clean=line_is_clean(line))
        finally:
            out.close()
        return

    outputs = [open_writer(settings, prefix) for prefix in ("k_start.", "k_mid.", "k_end.")]
    try:
        for line in lines:
            clean = line_is_clean(line)
            for out, grams in zip(outputs, kgrams_split(line, min_length, max_length)):
                out.add(grams, clean=clean)
    finally:
        for out in outputs:
            out.close()


##############
### C-gram ###
##############

def split_charset_runs(plaintext, classes):
    """Split plaintext into runs of a single charset. Returns every run, whatever its length."""
    runs = []
    buffer = []
    last_charset = None
    for char in plaintext:
        current_charset = classes.get(char, UNKNOWN)
        if current_charset == UNKNOWN or current_charset == last_charset:  # treat unknown as every set
            buffer.append(char)
            continue
        if last_charset == WORD_START and (current_charset == LOWER or current_charset == UPPER):
            # Second letter of a run: "Password" stays one run
            buffer.append(char)
            last_charset = current_charset
            continue
        if buffer:
            runs.append("".join(buffer))
        buffer = [char]
        last_charset = WORD_START if current_charset == LOWER or current_charset == UPPER else current_charset
    if buffer:
        runs.append("".join(buffer))
    return runs


def parse_filter(filter_item):
    """Returns the filter as a list of start/mid/end tokens (or the shape filter name itself)."""
    if filter_item in SHAPE_FILTERS:
        return filter_item
    tokens = []
    rest = filter_item
    while rest:
        for token in POSITION_TOKENS:
            if rest.startswith(token):
                tokens.append(token)
                rest = rest[len(token):]
                break
        else:
            raise UsageError("--filter value \"" + filter_item + "\" is not a valid filter and must consist exclusively of solo, duo, duostart, duoend, start, mid, and end - or any combination of 'start, mid, or end'. (ex: startmidmidend)")
    if not tokens:
        raise UsageError("Empty --filter value.")
    return tokens


def is_repetition(item):
    """"startstart" or "midendmidend" are covered by their shorter form already."""
    for i in range(2, len(item) // 2 + 1):
        if len(item) % i == 0 and item[:i] * (len(item) // i) == item:
            return True
    return False


def build_filters(filter_arg, combo_length):
    filter_items = [item for item in (filter_arg or "").split(",") if item]
    if combo_length:
        for i in range(1, combo_length + 1):
            for combination in product(POSITION_TOKENS, repeat=i):
                item = "".join(combination)
                if not is_repetition(item):
                    filter_items.append(item)
    filter_items = list(dict.fromkeys(filter_items))  # drop duplicates, keep order
    return [(item, parse_filter(item)) for item in filter_items]


def select_parts(spec, start, mids, end, part_count):
    """Picks the parts a filter asks for, or None if it does not apply to this many parts."""
    if spec == "solo":
        return [start] if part_count == 1 else None
    if spec in ("duo", "duostart", "duoend"):
        if part_count != 2:
            return None
        return {"duo": [start, end], "duostart": [start], "duoend": [end]}[spec]
    if part_count < 3:
        return None
    selected = []
    for token in spec:
        if token == "start":
            selected.append(start)
        elif token == "mid":
            selected += mids
        else:
            selected.append(end)
    return selected


def rule_bytes(part):
    """Hashcat rules work on bytes; anything not plainly printable is written as \\xHH."""
    return [chr(byte) if 0x21 <= byte <= 0x7e and byte != 0x5c else "\\x%02x" % byte
            for byte in part.encode("utf-8", "surrogateescape")]


def prepend_rule(part):
    return " ".join("^" + char for char in reversed(rule_bytes(part)))


def append_rule(part):
    return " ".join("$" + char for char in rule_bytes(part))


def insert_rules(mids, offset):
    """i-rules that insert each mid part after the previous one, starting at offset.
    Returns None when a part would need a position hashcat cannot express (above Z)."""
    rules = []
    for mid in mids:
        if offset >= len(RULE_POSITIONS):
            return None
        chars = rule_bytes(mid)
        rules.append(" ".join("i" + RULE_POSITIONS[offset] + char for char in reversed(chars)))
        offset += len(chars)
    return rules


def overwrite_rules(mids, offset):
    """o-rules that overwrite the characters from offset onwards with the mid parts.
    Returns None when a character would need a position hashcat cannot express (above Z)."""
    rules = []
    for mid in mids:
        chars = rule_bytes(mid)
        if offset + len(chars) > len(RULE_POSITIONS):
            return None
        rules.append(" ".join("o" + RULE_POSITIONS[offset + i] + char for i, char in enumerate(chars)))
        offset += len(chars)
    return rules


def is_valid_rule(rule):
    return len(rule) <= RULE_MAX_LENGTH and rule.count(" ") + 1 <= RULE_MAX_FUNCTIONS


class FilterOutputs:
    def __init__(self, settings):
        self.filters = settings["filters"]
        self.rulify = settings["rulify"]
        self.skipped_rules = 0
        self.gram_writers = {}
        self.rule_writers = {}
        for item, _ in self.filters:
            self.gram_writers[item] = open_writer(settings, "c_" + item + "_", 1 << 16)
            if self.rulify:
                self.rule_writers[item] = open_writer(dict(settings, output_file=settings["output_file"] + ".rule"), "c_" + item + "_", 1 << 16)

    def write(self, parts, clean):
        if not self.filters or not parts:
            return
        part_count = len(parts)
        start, mids, end = parts[0], parts[1:-1], parts[-1]
        for item, spec in self.filters:
            selected = select_parts(spec, start, mids, end, part_count)
            if selected:
                self.gram_writers[item].add(["".join(selected)], clean=clean)

        if not self.rulify:
            return
        start_offset = len(start.encode("utf-8", "surrogateescape"))
        start_rule = prepend_rule(start)
        end_rule = append_rule(end)
        inserted = insert_rules(mids, start_offset) if part_count >= 3 else []
        overwritten = overwrite_rules(mids, start_offset) if part_count >= 3 else []
        for item, spec in self.filters:
            uses_mid = part_count >= 3 and "mid" in spec
            rules = []
            # Without every mid part the rule would build something else, so leave it out.
            # Filters that do not use mid never look at the mid rules.
            for mid_rules in ([inserted, overwritten] if uses_mid else [inserted or []]):
                selected = select_parts(spec, start_rule, mid_rules, end_rule, part_count) if mid_rules is not None else None
                if selected:
                    rules.append(" ".join(selected))
                elif uses_mid:
                    self.skipped_rules += 1
            valid = [rule for rule in rules if is_valid_rule(rule)]
            self.skipped_rules += len(rules) - len(valid)
            self.rule_writers[item].add(valid, clean=True)

    def close(self):
        for writer in list(self.gram_writers.values()) + list(self.rule_writers.values()):
            writer.close()
        if self.skipped_rules:
            info("Skipped " + str(self.skipped_rules) + " rules that do not fit hashcat's limits ("
                 + str(RULE_MAX_FUNCTIONS) + " functions, " + str(RULE_MAX_LENGTH) + " characters, positions up to "
                 + RULE_POSITIONS[-1] + ").")


def glue_parts(runs, in_range, grams, filter_outputs, clean):
    """Glue runs that have a single character between them ("pass" "!" "word" -> "pass!word")"""
    while True:
        glued_any = False
        new_runs = []
        i = 0
        while i < len(runs):
            if i + 2 < len(runs) and len(runs[i + 1]) == 1:
                glued = runs[i] + runs[i + 1] + runs[i + 2]
                glued_any = True
                if in_range(glued):
                    grams.append(glued)
                new_runs.append(glued)
                i += 3
            else:
                new_runs.append(runs[i])
                i += 1

        if not glued_any:
            return
        filter_outputs.write([run for run in new_runs if in_range(run)], clean)
        runs = new_runs


def cgramify(settings):
    min_length, max_length = settings["min_length"], settings["max_length"]
    passes = [STRICT_CLASSES]
    if settings["mixed"]:
        # Mixed case + less strict special check, then mixed numeric case + less strict special check
        passes += [MIXED_CLASSES, MIXED_NUMERIC_CLASSES]

    def in_range(run):
        return min_length <= len(run) <= max_length

    out = open_writer(settings, "c_")
    filter_outputs = FilterOutputs(settings)
    try:
        for line in read_lines(settings["input_file"]):
            clean = line_is_clean(line)
            grams = []
            for classes in passes:
                runs = split_charset_runs(line, classes)
                matches = [run for run in runs if in_range(run)]
                grams += matches
                filter_outputs.write(matches, clean)
                glue_parts(runs, in_range, grams, filter_outputs, clean)
            out.add(grams, clean=clean)
    finally:
        out.close()
        filter_outputs.close()


############
### Main ###
############

def parse_int(args, option, minimum):
    value = args.get(option)
    if value is None:
        return None
    try:
        number = int(value)
    except ValueError:
        raise UsageError(option + " should be a whole number.")
    if number < minimum:
        raise UsageError(option + " should be " + str(minimum) + " or more.")
    return number


def build_settings(args):
    if args["word"]:
        mode, default_min, default_max = "word", 1, 10
    elif args["character"]:
        mode, default_min, default_max = "character", 3, 32 if args["--rolling"] else 8
    else:
        mode, default_min, default_max = "charset", 3, 32

    min_length = parse_int(args, "--min-length", 1)
    max_length = parse_int(args, "--max-length", 1)
    min_length = default_min if min_length is None else min_length
    max_length = default_max if max_length is None else max_length
    if min_length > max_length:
        raise UsageError("Min Length (" + str(min_length) + ") should be smaller or equal to Max length (" + str(max_length) + ").")

    min_count = parse_int(args, "--min-count", 1)
    count = bool(args["--count"]) or min_count is not None
    if count and args["--append"]:
        raise UsageError("--count/--min-count cannot be combined with --append.")

    input_file = args["<input_file>"]
    if input_file == "-" and sys.stdin is None:
        raise UsageError("STDIN is not available.")
    if input_file != "-" and (not os.path.exists(input_file) or os.path.isdir(input_file)):
        raise UsageError("Input file does not exist.")

    settings = {
        "mode": mode,
        "input_file": input_file,
        "output_file": None if args["--stdout"] else args["<output_file>"],
        "min_length": min_length,
        "max_length": max_length,
        "count": count,
        "min_count": min_count or 1,
        "append": bool(args["--append"]),
        "ngram_more": bool(args.get("--ngram-more")),
        "per_line": bool(args.get("--per-line")),
        "rolling": bool(args.get("--rolling")),
        "mixed": bool(args.get("--mixed")),
        "rulify": bool(args.get("--cgram-rulify-beta")),
        "filters": [],
        "written_files": [],
    }

    if mode == "character" and args["--stdout"] and not settings["rolling"]:
        raise UsageError("Cannot use --stdout without --rolling")

    if mode == "charset":
        settings["filters"] = build_filters(args["--filter"], parse_int(args, "--filter-combo-length", 1))
        if settings["filters"] and args["--stdout"]:
            raise UsageError("--filter and --filter-combo-length write separate files and cannot be used with --stdout.")
        if settings["rulify"] and not settings["filters"]:
            raise UsageError("--cgram-rulify-beta converts the --filter outputs, so it needs --filter or --filter-combo-length.")
        if min_length != 1 and any("mid" in spec for _, spec in settings["filters"]):
            info("Warning: You are using a filter with 'mid'. It is highly advised to set --min-length to 1 for this.")

    check_outputs(settings)
    return settings


def main():
    global QUIET
    args = docopt(__doc__, version=VERSION)
    QUIET = bool(args["--quiet"]) or sys.stderr is None
    try:
        settings = build_settings(args)
        {"word": ngramify, "character": kgramify, "charset": cgramify}[settings["mode"]](settings)
    except UsageError as error:
        error_message(error)
        sys.exit(1)

    if settings["written_files"] and not settings["count"]:
        info("")
        info("Don't forget to de-duplicate and sort the output (or use --count next time).\nRecommended commands:")
        for item in settings["written_files"]:
            info("LC_ALL=C sort \"" + item + "\" | uniq -c | LC_ALL=C sort -rn | awk '$1 >= 5' | sed -E 's/^ *[0-9]+ //' > \"" + item + ".sorted\"")


QUIET = False

if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        # Output was piped into something like head that stopped reading
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
