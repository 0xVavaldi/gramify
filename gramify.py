#!/usr/bin/env python3
"""n-gram generator on word, char and charset basis

Usage:
  gramify.py word <input_file> (<output_file>|--stdout) [--min-length=<int>] [--max-length=<int>] [--ngram-more]
  gramify.py character <input_file> (<output_file>|--stdout) [--min-length=<int>] [--max-length=<int>] [--rolling]
  gramify.py charset <input_file> (<output_file>|--stdout) [--min-length=<int>] [--max-length=<int>] [--mixed] [--filter=<str>] [--filter-combo-length=<str>] [--cgram-rulify-beta]
  gramify.py (-h | --help)
  gramify.py --version

Options:
  -h --help                     Show this screen.
  --version                     Show version.
  --min-length=<int>            Minimum size of k,n,c-gram output.
  --max-length=<int>            Maximum size of k,n,c-gram output.
  --stdout                      Print output to STDOUT instead of a file. Not available when several files are
                                written: character mode without rolling, or charset mode with filters.
  --rolling                     Make kgrams in one file based on length instead of into three groups of start, mid, end.
  --mixed                       Allow for mixed charset cgrams
  --filter=<str>                Filter for specific outputs using solo, duo, duostart, duoend, start, mid, and end. (Default uses no filter)
  --filter-combo-length=<int>   Create automatic filter combinations of start,mid,end (startmid,startmidmidendend) based on length [BETA]
  --cgram-rulify-beta           Convert cgram output into hashcat-rules [BETA]
  --ngram-more                  Add extra candidates by removing casing and special characters

Input and output:
  Use - as <input_file> to read from STDIN. Status messages go to STDERR, so --stdout only contains grams.
  The output contains duplicates; count them with e.g. gramify.py character - --stdout --rolling | sort | uniq -c | sort -rn

Gram-types:
  K-Gram (Character):           Letter based https://nlp.stanford.edu/IR-book/html/htmledition/k-gram-indexes-for-wildcard-queries-1.html
  N-Gram (Word):                Word based https://en.wikipedia.org/wiki/N-gram
  C-Gram (Charset):             Charset boundry inspired by https://github.com/hops/pack2/blob/master/src/cgrams.rs

Filter:
  Format filter using a comma separated string of combinations of start, mid, and end.
  using --filter 'solo' will output 1 file containing all passwords with exclusively 1 element.
  using --filter 'duo,duostart,duoend' will output 3 files containing all passwords with exclusively 2 element.
  using --filter 'start,mid,end' will output 3 files containing the first element, the middle elements and the last element respectively (does not include solo or duo).
  using --filter 'startmid' will output 1 file containing the first and middle elements, but not the last which is perfect for -a6 hybrid attacks.
  using --filter 'midend' will output 1 file containing the middle and end elements, but not the first which is perfect for -a7 hybrid attacks.
  You can make any combination yourself. "startmidstartmidendmidstart" for example.
  Recommended filters to play with are listed above
"""
import re
import os
import io
import sys
import errno
import binascii
from itertools import permutations
from tqdm import tqdm
from docopt import docopt

sys.setrecursionlimit(5000)
output_file_names = []


def open_input(input_file):
    """Use - as <input_file> to read from STDIN"""
    if input_file == "-":
        if sys.stdin is None:
            print("STDIN is not available.", file=sys.stderr)
            sys.exit(1)
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="ignore")
    return open(input_file, "r", encoding="utf-8", errors="ignore")


def open_output(output_file, use_stdout):
    """With --stdout the output goes to STDOUT instead of a file"""
    if use_stdout:
        return sys.stdout
    print("Writing output to: " + output_file, file=sys.stderr)
    output_file_names.append(output_file)
    return open(output_file, "a+", encoding="utf-8", errors="ignore")


def close_output(output_file_handler):
    if output_file_handler is sys.stdout:
        output_file_handler.flush()
    else:
        output_file_handler.close()


def output_filter_writer(output_filter, output_filter_file_handler, matches):
    for filter_item in output_filter:
        filter_output = []
        if(filter_item == "solo" and len(matches) == 1):
            output_filter_file_handler[filter_item].write(matches[0] + "\n")
            continue

        if len(matches) < 2: continue
        if filter_item == "solo": continue

        if len(matches) == 2:
            if filter_item == "duostart":
                output_filter_file_handler[filter_item].write(matches[0] + "\n")
                continue
            if filter_item == "duoend":
                output_filter_file_handler[filter_item].write(matches[1] + "\n")
                continue
            if filter_item == "duo":
                output_filter_file_handler[filter_item].write(matches[0] + matches[1] + "\n")
                continue
        if len(matches) < 3: continue
        if filter_item == "duostart": continue
        if filter_item == "duoend": continue
        if filter_item == "duo": continue
        if filter_item == "solo": continue

        start = matches[0]
        mid = matches[1:-1]
        end = matches[-1]

        _filter = filter_item
        filter_output = []
        while _filter != "":
            if _filter.startswith("start"):
                filter_output.append(start)
                _filter = _filter[len("start"):]
                continue

            if _filter.startswith("mid"):
                filter_output += mid
                _filter = _filter[len("mid"):]
                continue

            if _filter.startswith("end"):
                filter_output.append(end)
                _filter = _filter[len("end"):]
                continue

        for item in filter_output:
            output_filter_file_handler[filter_item].write(item)
        if len(filter_output) > 0:
            output_filter_file_handler[filter_item].write("\n")


def output_rule_filter_writer(output_filter, output_rule_file_handler, matches):
    matches_copy = matches.copy()
    index_convert = [x for x in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    start_length = 0
    
    # Convert to rules
    if len(matches_copy) >= 1:
        start_length = len(matches_copy[0])
        # start
        buffer = []
        for letter in matches_copy[0][::-1]:
            buffer.append("^" + letter)
        matches_copy[0] = " ".join(buffer)

    if len(matches_copy) >= 2:
        # end
        buffer = []
        for letter in matches_copy[-1]:
            buffer.append("$" + letter)
        matches_copy[-1] = " ".join(buffer)

    if len(matches_copy) >= 3:
        # mid
        offset = start_length
        index = 1
        matches_middle = matches_copy[1:-1].copy()

        for mid_part in matches_middle:
            if offset > 35:
                del matches_copy[index]
                continue
            buffer = []
            for letter in mid_part[::-1]:
                buffer.append("i" + index_convert[offset] + letter)
            offset += len(mid_part)
            matches_copy[index] = " ".join(buffer)
            index += 1

    # Write rules
    for filter_item in output_filter:
        filter_output = []
        if(filter_item == "solo" and len(matches_copy) == 1):
            output_rule_file_handler[filter_item].write(matches_copy[0] + "\n")
            continue

        if len(matches_copy) < 2: continue
        if filter_item == "solo": continue

        if len(matches_copy) == 2:
            if filter_item == "duostart":
                output_rule_file_handler[filter_item].write(matches_copy[0] + "\n")
                continue
            if filter_item == "duoend":
                output_rule_file_handler[filter_item].write(matches_copy[1] + "\n")
                continue
            if filter_item == "duo":
                output_rule_file_handler[filter_item].write(matches_copy[0] + matches_copy[1] + "\n")
                continue
        if len(matches_copy) < 3: continue
        if filter_item == "solo": continue
        if filter_item == "duostart": continue
        if filter_item == "duoend": continue
        if filter_item == "duo": continue

        start = matches_copy[0]
        mid = matches_copy[1:-1]
        end = matches_copy[-1]

        _filter = filter_item
        filter_output = []
        while _filter != "":
            if _filter.startswith("start"):
                filter_output.append(start)
                _filter = _filter[len("start"):]
                continue

            if _filter.startswith("mid"):
                filter_output += mid
                _filter = _filter[len("mid"):]
                continue

            if _filter.startswith("end"):
                filter_output.append(end)
                _filter = _filter[len("end"):]
                continue

        if "" in filter_output: filter_output.remove("")
        if len(filter_output) > 0:
            output_rule_file_handler[filter_item].write(" ".join(filter_output) + "\n")


def output_rule_filter_writer_overwrite(output_filter, output_rule_file_handler, matches):
    matches_copy = matches.copy()
    index_convert = [x for x in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    start_length = 0
    
    # Convert to rules
    if len(matches_copy) >= 1:
        start_length = len(matches_copy[0])
        # start
        buffer = []
        for letter in matches_copy[0][::-1]:
            buffer.append("^" + letter)
        matches_copy[0] = " ".join(buffer)

    if len(matches_copy) >= 2:
        # end
        buffer = []
        for letter in matches_copy[-1]:
            buffer.append("$" + letter)
        matches_copy[-1] = " ".join(buffer)

    if len(matches_copy) >= 3:
        # mid
        offset = start_length
        index = 1
        matches_middle = matches_copy[1:-1].copy()

        for mid_part in matches_middle:
            if offset > 35:
                del matches_copy[index]
                continue
            buffer = []
            for letter in mid_part:
                if offset > 35:
                    continue
                buffer.append("o" + index_convert[offset] + letter)
                offset+= 1
            matches_copy[index] = " ".join(buffer)
            index += 1

    # Write rules
    for filter_item in output_filter:
        filter_output = []
        if len(matches_copy) < 3: continue
        if filter_item == "solo": continue
        if filter_item == "duostart": continue
        if filter_item == "duoend": continue
        if filter_item == "duo": continue

        start = matches_copy[0]
        mid = matches_copy[1:-1]
        end = matches_copy[-1]

        _filter = filter_item
        filter_output = []
        has_mid = False
        while _filter != "":
            if _filter.startswith("start"):
                filter_output.append(start)
                _filter = _filter[len("start"):]
                continue

            if _filter.startswith("mid"):
                has_mid = True
                filter_output += mid
                _filter = _filter[len("mid"):]
                continue

            if _filter.startswith("end"):
                filter_output.append(end)
                _filter = _filter[len("end"):]
                continue

        if not has_mid: continue
        if "" in filter_output: filter_output.remove("")
        if len(filter_output) > 0:
            output_rule_file_handler[filter_item].write(" ".join(filter_output) + "\n")

def decode_hex(plaintext):
    """Decode hashcat's $HEX[] notation. Anything that is not valid hex is used as-is, like hashcat does."""
    if plaintext.startswith("$HEX[") and plaintext.endswith("]"):
        try:
            return binascii.unhexlify(plaintext[5:-1]).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            pass
    return plaintext


def alphanum_string(stringx):
    alphanumeric = ""
    for character in stringx:
        if character.isalnum():
            alphanumeric += character
    return alphanumeric

def ngramify(docopt_args):
    input_file = docopt_args.get('<input_file>')
    output_file = docopt_args.get('<output_file>')
    ngram_more = bool(docopt_args['--ngram-more'])
    use_stdout = bool(docopt_args['--stdout'])
    if ARGS.get('--min-length') is None:
        min_length = 1
    else:
        min_length = int(docopt_args.get('--min-length'))

    if ARGS.get('--max-length') is None:
        max_length = 10
    else:
        max_length = int(docopt_args.get('--max-length'))

    input_file_handler = open_input(input_file)
    output_file_handler = open_output("n_" + str(output_file), use_stdout)

    data_raw = ""
    for line in input_file_handler:
        data_raw += decode_hex(line.rstrip("\r\n")) + " "

    data = re.split(" ", data_raw)
    data = list(filter(None, data))

    for i in range(min_length, max_length+1, 1):
        for j in range(0, len(data)-i+1, 1):
            output_set = data[j:j+i]
            output_file_handler.write(" ".join(output_set) + "\n")

    if ngram_more:
        new_data = []
        for word in data:
            if alphanum_string(word):
                new_data.append(alphanum_string(word))
        data = new_data

        for i in range(min_length, max_length+1, 1):
            for j in range(0, len(data)-i+1, 1):
                output_set = data[j:j+i]
                output_file_handler.write(" ".join(output_set) + "\n")

        for i in range(min_length, max_length+1, 1):
            for j in range(0, len(data)-i+1, 1):
                output_set = data[j:j+i]
                output_file_handler.write(" ".join(output_set).lower() + "\n")

    close_output(output_file_handler)
    input_file_handler.close()


def kgramify(docopt_args):
    input_file = docopt_args['<input_file>']
    output_file = docopt_args['<output_file>']
    rolling = bool(docopt_args['--rolling'])
    use_stdout = bool(docopt_args['--stdout'])

    if ARGS.get('--min-length') is None:
        min_length = 3
    else:
        min_length = int(docopt_args.get('--min-length'))


    if ARGS.get('--max-length') is None:
        max_length = 32 if rolling else 8
    else:
        max_length = int(docopt_args.get('--max-length'))

    if rolling:
        in_handler = open_input(input_file)
        out_handler = open_output("k_rolling." + str(output_file), use_stdout)

        for line in in_handler:
            original_plaintext = decode_hex(line.rstrip("\r\n"))
            for i in range(min_length, max_length+1):
                for j in range(0, len(original_plaintext)+(1-i)):
                    out_handler.write(original_plaintext[j:j+i] + "\n")

        in_handler.close()
        close_output(out_handler)

    else:
        if use_stdout:
            print("Cannot use --stdout without --rolling: start, mid and end are written to three files.", file=sys.stderr)
            sys.exit(1)

        with open_input(input_file) as fp:
            line = True
            start_file_handler = open_output("k_start." + output_file, False)
            mid_file_handler = open_output("k_mid." + output_file, False)
            end_file_handler = open_output("k_end." + output_file, False)
            while line:
                line = fp.readline()
                original_plaintext = decode_hex(line.rstrip("\r\n"))
                return_array = [[],[],[]]
                if len(original_plaintext) > 256:  # prevent recursion depth
                    continue
                return_array = kgramify_process(return_array, original_plaintext, 0, 1, min_length, max_length)  # minus one for array offset
                for item in return_array[0]:
                    start_file_handler.write(item + "\n")
                for item in return_array[1]:
                    mid_file_handler.write(item + "\n")
                for item in return_array[2]:
                    end_file_handler.write(item + "\n")

            start_file_handler.close()
            mid_file_handler.close()
            end_file_handler.close()


def kgramify_process(return_array, input_word, start, end, min_length, max_length):
    if start >= len(input_word) or len(input_word) <= min_length:
        return return_array

    elif start == 0 and end-start == max_length and end < len(input_word):
        # First section & Mid section
        next_start = start+1
        next_end = end+1
        if end-start >= min_length:
            return_array[0].append(input_word[start:end])
            return_array[1].append(input_word[start:end])
    elif start > 0 and end-start == max_length and end < len(input_word):
        # Middle section
        next_start = start+1
        next_end = end+1
        if end-start >= min_length:
            return_array[1].append(input_word[start:end])
    elif end-start == max_length and end == len(input_word):
        # Mid and End section
        next_start = start+1
        next_end = end
        if end-start >= min_length:
            return_array[1].append(input_word[start:end])
            return_array[2].append(input_word[start:end])

    elif start == 0 and end < len(input_word) and end-start <= max_length and end-start < len(input_word)-1:
        # First section
        next_start = start
        next_end = end+1
        if end-start >= min_length:
            return_array[0].append(input_word[start:end])

    elif start == 0 and end < len(input_word) and end-start <= max_length and end-start == len(input_word)-1:
        # First section
        next_start = start+1
        next_end = end+1
        if end-start >= min_length:
            return_array[0].append(input_word[start:end])
    elif start > 0 and end == len(input_word) and end-start < max_length:
        # Last section
        next_start = start+1
        next_end = end
        if end-start >= min_length:
            return_array[2].append(input_word[start:end])

    return kgramify_process(return_array, input_word, next_start, next_end, min_length, max_length)

def generate_permutation_with_repeats(elements, length):
    if length == 0:
        return [""]
    
    permutations = []
    for element in elements:
        sub_permutations = generate_permutation_with_repeats(elements, length - 1)
        for sub_permutation in sub_permutations:
            permutations.append(element + sub_permutation)
    
    return permutations

def has_repeating_substrings(s):
    for i in range(len(s) - 1):
        if s[i:i + 2] in s[i + 2:]:
            return True
    return False

def glue_parts(cgram_rulify, min_length, max_length, output_filter, output_file_handler, output_filter_file_handler, output_rule_file_handler, all_matches):
    while True:
        has_new_matches = False
        new_matches = []
        i = 0
        while i < len(all_matches):
            if i + 2 < len(all_matches) and len(all_matches[i + 1]) == 1:
                has_new_matches = True
                new_match = all_matches[i] + all_matches[i + 1] + all_matches[i + 2]
                if len(new_match) >= min_length and len(new_match) <= max_length:
                    output_file_handler.write(new_match + "\n")
                new_matches.append(new_match)
                i += 3
            else:
                new_matches.append(all_matches[i])
                i += 1

        if not has_new_matches: return
        in_range_matches = [match for match in new_matches if min_length <= len(match) <= max_length]
        output_filter_writer(output_filter, output_filter_file_handler, in_range_matches)
        if cgram_rulify: output_rule_filter_writer(output_filter, output_rule_file_handler, in_range_matches)
        if cgram_rulify: output_rule_filter_writer_overwrite(output_filter, output_rule_file_handler, in_range_matches)

        all_matches = new_matches

def blocks(files, size=65536):
    while True:
        b = files.read(size)
        if not b: break
        yield b

def cgramify(docopt_args):
    input_file = docopt_args['<input_file>']
    output_file = docopt_args['<output_file>']
    use_stdout = bool(docopt_args['--stdout'])
    lowercase =    set(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'])
    uppercase =    set(['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'])
    numeric =      set(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])
    special =      set(['!', '"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ';', '<', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '+', ' ', ':', '='])
    special_full = set(['!', '"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ';', '<', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '+', ' ', ':', '=', '\'', '-'])
    cgram_rulify = False
    # does not include ' and - because of their common use in normal language

    if ARGS.get('--min-length') is None:
        min_length = 3
    else:
        min_length = int(docopt_args.get('--min-length'))

    if ARGS.get('--cgram-rulify-beta'):
        cgram_rulify = True

    if ARGS.get('--max-length') is None:
        max_length = 32
    else:
        max_length = int(docopt_args.get('--max-length'))

    if ARGS.get('--filter') is None:
        output_filter = []
    else:
        if ARGS.get('--filter') is not None:
            output_filter = docopt_args.get('--filter')
            output_filter = output_filter.split(",")
            if "" in output_filter: output_filter.remove("")

    if ARGS.get('--filter-combo-length') is not None:
        output_filter_count = int(docopt_args.get('--filter-combo-length'))
        all_combinations = []
        for i in range(1, output_filter_count+1):
            all_combinations += generate_permutation_with_repeats(["start", "mid", "end"], i)

        combinations_output = all_combinations.copy()
        for item in all_combinations:
            res = ""
            for i in range(1, len(item)//2 + 1):
                if (not len(item) % len(item[0:i]) and item[0:i] *
                    (len(item)//len(item[0:i])) == item):
                    res = item[0:i]
            
            if len(res) > 1:
                combinations_output.remove(item)
        output_filter += combinations_output

    output_filter = list(dict.fromkeys(output_filter))  # a combo can repeat a --filter value
    for item in output_filter:  # using this more complex filter to allow for more complex filters in the future such as startmidstartend
        original_item = item
        if item in ["solo", "duo", "duostart", "duoend"]: continue
        while(len(item) > 0):
            match = False
            if item.startswith("start"):
                match = True
                item = item[len("start"):]
            if item.startswith("mid"):
                if(min_length != 1):
                    print("Warning: You are using a filter with 'mid'. It is highly advised to set --min-length to 1 for this.", file=sys.stderr)
                match =  True
                item = item[len("mid"):]
            if item.startswith("end"):
                match =  True
                item = item[len("end"):]
            if not match:
                break
        if(len(item) > 0):
            print("--filter value \"" + original_item + "\" is not a valid filter and must consist exclusively of solo, duo, duostart, duoend, start, mid, and end - or any combination of 'start, mid, or end'. (ex: startmidmidend)", file=sys.stderr)
            sys.exit(1)

    if use_stdout and output_filter:
        print("Cannot use --stdout with --filter or --filter-combo-length: every filter is written to its own file.", file=sys.stderr)
        sys.exit(1)

    line_count = None  # STDIN can only be read once, so the progress bar has no total
    if input_file != "-":
        print("Counting lines", file=sys.stderr)
        with open(input_file, "r",encoding="utf-8",errors='ignore') as f:
            line_count = sum(bl.count("\n") for bl in blocks(f))

    input_file_handler = open_input(input_file)
    output_file_handler = open_output("c_" + str(output_file), use_stdout)

    output_filter_file_handler = {}
    for item in output_filter:
        output_filter_file_handler[item] = open_output("c_" + item + "_" + output_file, False)

    output_rule_file_handler = {}
    if cgram_rulify:
        for item in output_filter:
            output_rule_file_handler[item] = open_output("c_" + item + "_" + output_file + ".rule", False)

    ########################
    ### Start processing ###
    ########################
    for line in tqdm(input_file_handler, bar_format='{l_bar}{bar:50}{r_bar}{bar:-50b}', total=line_count, miniters=10000):
        original_plaintext = decode_hex(line.rstrip("\r\n"))

        last_charset = 'empty'
        character_buffer = []
        matches = []
        all_matches = []
        for char in original_plaintext:
            is_lowercase = True if char in lowercase else False
            if not is_lowercase:
                is_uppercase = True if char in uppercase else False

            if len(character_buffer) == 0 and (is_lowercase or is_uppercase):
                current_charset = 'mixedcase'
            elif is_lowercase:
                current_charset = 'lowercase'
            elif is_uppercase:
                current_charset = 'uppercase'
            elif char in numeric:
                current_charset = 'numeric'
            elif char in special_full:  # use special full on the most strict pass
                current_charset = 'special'
            else:
                current_charset = 'unknown'

            if current_charset == last_charset or current_charset == 'unknown':  # treat unknown as every set
                character_buffer.append(char)
                continue

            if current_charset in ['lowercase', 'uppercase'] and last_charset == 'mixedcase':
                character_buffer.append(char)
                last_charset = current_charset
                continue

            if len(character_buffer) > 0:
                all_matches.append("".join(character_buffer))
            if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                output_file_handler.write("".join(character_buffer) + "\n")
                matches.append("".join(character_buffer))
            if(current_charset == 'lowercase' or current_charset == 'uppercase'):
                current_charset = 'mixedcase'

            last_charset = current_charset
            character_buffer = [char]

        if len(character_buffer) > 0:
            all_matches.append("".join(character_buffer))
        if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
            output_file_handler.write("".join(character_buffer) + "\n")
            matches.append("".join(character_buffer))

        # Output matches into filter outputs
        output_filter_writer(output_filter, output_filter_file_handler, matches)
        if cgram_rulify: output_rule_filter_writer(output_filter, output_rule_file_handler, matches)
        if cgram_rulify: output_rule_filter_writer_overwrite(output_filter, output_rule_file_handler, matches)

        # get new matches by glueing together parts that have 1-length in between
        glue_parts(cgram_rulify, min_length, max_length, output_filter, output_file_handler, output_filter_file_handler, output_rule_file_handler, all_matches)

        if ARGS.get('--mixed'):
            # Mixed case + less strict special check
            lowercased = False
            matches = []
            all_matches = []
            character_buffer = []
            last_charset = "empty"
            for char in original_plaintext:
                if char in lowercase or char in uppercase:
                    current_charset = 'mixedcase'
                elif char in numeric:
                    current_charset = 'numeric'
                elif char in special:
                    current_charset = 'special'
                else:
                    current_charset = 'unknown'

                if current_charset == last_charset or current_charset == 'unknown':  # treat unknown as every set
                    character_buffer.append(char)
                else:
                    if len(character_buffer) > 0:
                        all_matches.append("".join(character_buffer))
                    if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                        output_file_handler.write("".join(character_buffer) + "\n")
                        matches.append("".join(character_buffer))
                    last_charset = current_charset
                    character_buffer = [char]
            
            if len(character_buffer) > 0:
                all_matches.append("".join(character_buffer))
            if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                output_file_handler.write("".join(character_buffer) + "\n")
                matches.append("".join(character_buffer))

            # Output matches into filter outputs
            output_filter_writer(output_filter, output_filter_file_handler, matches)
            if cgram_rulify: output_rule_filter_writer(output_filter, output_rule_file_handler, matches)
            if cgram_rulify: output_rule_filter_writer_overwrite(output_filter, output_rule_file_handler, matches)

            # get new matches by glueing together parts that have 1-length in between
            glue_parts(cgram_rulify, min_length, max_length, output_filter, output_file_handler, output_filter_file_handler, output_rule_file_handler, all_matches)


            matches = []
            all_matches = []
            character_buffer = []
            last_charset = "empty"

            # Mixed numeric case + less strict special check
            for char in original_plaintext:
                if char in lowercase or char in uppercase or char in numeric:
                    current_charset = 'mixedcasenumeric'
                elif char in special:
                    current_charset = 'special'
                else:
                    current_charset = 'unknown'

                if current_charset == last_charset or current_charset == 'unknown':  # treat unknown as every set
                    character_buffer.append(char)
                else:
                    if len(character_buffer) > 0:
                        all_matches.append("".join(character_buffer))
                    if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                        output_file_handler.write("".join(character_buffer) + "\n")
                        matches.append("".join(character_buffer))
                    last_charset = current_charset
                    character_buffer = [char]

            if len(character_buffer) > 0:
                all_matches.append("".join(character_buffer))
            if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                output_file_handler.write("".join(character_buffer) + "\n")
                matches.append("".join(character_buffer))

            # Output matches into filter outputs
            output_filter_writer(output_filter, output_filter_file_handler, matches)
            if cgram_rulify: output_rule_filter_writer(output_filter, output_rule_file_handler, matches)
            if cgram_rulify: output_rule_filter_writer_overwrite(output_filter, output_rule_file_handler, matches)

            # get new matches by glueing together parts that have 1-length in between
            glue_parts(cgram_rulify, min_length, max_length, output_filter, output_file_handler, output_filter_file_handler, output_rule_file_handler, all_matches)

    # Close file handles
    input_file_handler.close()
    close_output(output_file_handler)
    for filter_item in output_filter:
        output_filter_file_handler[filter_item].close()
    for filter_item in output_rule_file_handler:
        output_rule_file_handler[filter_item].close()

def main():
    if ARGS.get('<input_file>') != "-" and not os.path.exists(ARGS.get('<input_file>')):
        print("Input file does not exist.", file=sys.stderr)
        sys.exit(1)

    if ARGS.get('--min-length') is not None and int(ARGS.get('--min-length')) < 0:
        print("Min Length should be greater than 0.", file=sys.stderr)
        sys.exit(1)

    if ARGS.get('--max-length') is not None and int(ARGS.get('--max-length', 1)) < 0:
        print("Max Length should be greater than 0.", file=sys.stderr)
        sys.exit(1)

    if ARGS.get('--min-length') is not None and ARGS.get('--max-length') is not None:
        if int(ARGS.get('--min-length')) > int(ARGS.get('--max-length')):
            print("Min Length should be smaller or equal to Max length.", file=sys.stderr)
            sys.exit(1)

    if ARGS.get('--filter-combo-length') is not None and not ARGS.get('--filter-combo-length').isnumeric():
        print("Filter combo length should be numeric", file=sys.stderr)
        sys.exit(1)

    if ARGS.get('--stdout'):
        # Grams are UTF-8, whatever the console encoding is
        sys.stdout.reconfigure(encoding="utf-8", errors="ignore")

    if ARGS.get('word'):
        ngramify(ARGS)

    if ARGS.get('character'):
        kgramify(ARGS)

    if ARGS.get('charset'):
        cgramify(ARGS)

    if not output_file_names:
        return
    print(file=sys.stderr)
    print("Don't forget to de-duplicate and sort the output.\nRecommended commands:", file=sys.stderr)
    for item in output_file_names:
        print("cat \"" + item + "\" | sort | uniq -c | sort -rn | awk '($1 >= 5)' | awk '{if ($1 >=1) {$1=\"\"; print substr($0, index($0, $2))}}' > \"" + item + ".sorted\"", file=sys.stderr)


if __name__ == '__main__':
    ARGS = docopt(__doc__, version='2.5')
    try:
        main()
    except OSError as error:
        # The reader of --stdout stopped early (e.g. "| head"); Windows reports this as EINVAL
        if not (ARGS.get('--stdout') and (isinstance(error, BrokenPipeError) or error.errno == errno.EINVAL)):
            raise
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)

