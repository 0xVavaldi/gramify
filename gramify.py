"""n-gram generator on word, char and charset basis

Usage:
  gramify.py word <input_file> <output_file> [--min-length=<int>] [--max-length=<int>]
  gramify.py character <input_file> <output_file> [--min-length=<int>] [--max-length=<int>] [--rolling]
  gramify.py charset <input_file> <output_file> [--min-length=<int>] [--max-length=<int>] [--mixed] [--filter=<str>]
  gramify.py (-h | --help)
  gramify.py --version

Options:
  -h --help                     Show this screen.
  --version                     Show version.
  --min-length=<int>            Minimum size of k,n,c-gram output.
  --max-length=<int>            Maximum size of k,n,c-gram output.
  --rolling                     Make kgrams in one file based on length instead of into three groups of start, mid, end.
  --mixed                       Allow for mixed charset cgrams
  --filter=<str>                Filter for specific outputs using start, mid, end. (Default uses no filter)

Gram-types:
  K-Gram (Character):           Letter based https://nlp.stanford.edu/IR-book/html/htmledition/k-gram-indexes-for-wildcard-queries-1.html
  N-Gram (Word):                Word based https://en.wikipedia.org/wiki/N-gram
  C-Gram (Charset):             Charset boundry inspired by https://github.com/hops/pack2/blob/master/src/cgrams.rs

Filter:
  Format filter using a comma separated string of combinations of start, mid, and end.
  using --filter 'solo' will output 1 file containing all passwords with exclusively 1 element.
  using --filter 'start,mid,end' will output 3 files containing the first element, the middle elements and the last element respectively (does not include solo).
  using --filter 'startmid' will output 1 file containing the first and middle elements, but not the last which is perfect for -a6 hybrid attacks.
  using --filter 'midend' will output 1 file containing the middle and end elements, but not the first which is perfect for -a7 hybrid attacks.
"""
import re
import os
import sys
from docopt import docopt
sys.setrecursionlimit(5000)


def alphanum_string(stringx):
    alphanumeric = ""
    for character in stringx:
        if character.isalnum():
            alphanumeric += character
    return alphanumeric

def ngramify(docopt_args):
    input_file = docopt_args.get('<input_file>')
    output_file = docopt_args.get('<output_file>')
    if ARGS.get('--min-length') is None:
        min_length = 1
    else:
        min_length = int(docopt_args.get('--min-length'))

    if ARGS.get('--max-length') is None:
        max_length = 10
    else:
        max_length = int(docopt_args.get('--max-length'))

    input_file_handler = open(input_file, "r", encoding="utf-8", errors="ignore")
    output_file_handler = open("n_" + output_file, "a+", encoding="utf-8", errors="ignore")
    print("Writing output to: n_" + output_file)
    data_raw = ""
    for line in input_file_handler:
        data_raw += line.rstrip("\n") + " "


    data = re.split(" ", data_raw)
    data = list(filter(None, data))

    for i in range(min_length, max_length+1, 1):
        for j in range(0, len(data)-1, 1):
            output_set = data[j:j+i]
            output_string = " ".join(output_set)
            # if output_string[-1] in ["?", ".", "!", ",", ";", "\"", "'"]:
            output_file_handler.write(output_string + "\n")

    new_data = []
    for word in data:
        new_data.append(alphanum_string(word))
    data = new_data

    for i in range(min_length, max_length+1, 1):
        for j in range(0, len(data)-1, 1):
            output_set = data[j:j+i]
            output_file_handler.write(" ".join(output_set) + "\n")
    output_file_handler.close()
    input_file_handler.close()


def kgramify(docopt_args):
    input_file = docopt_args['<input_file>']
    output_file = docopt_args['<output_file>']
    rolling = bool(docopt_args['--rolling'])

    if ARGS.get('--min-length') is None:
        min_length = 4
    else:
        min_length = int(docopt_args.get('--min-length'))


    if ARGS.get('--max-length') is None:
        max_length = 32 if rolling else 8
    else:
        max_length = int(docopt_args.get('--max-length'))

    if rolling:
        print("Writing output to: k_rolling." + output_file)
        in_handler = open(input_file, encoding="utf-8", errors="ignore")
        out_handler = open("k_rolling."+ output_file, "a+", encoding="utf-8", errors="ignore")
        for line in in_handler:
            original_plaintext = line.rstrip("\n").rstrip("\r")
            for i in range(min_length, max_length+1):
                for j in range(0, len(original_plaintext)+(1-i)):
                    out_handler.write(original_plaintext[j:j+i] + "\n")

        in_handler.close()
        out_handler.close()

    else:
        print("Writing output to: k_start." + output_file)
        print("Writing output to: k_mid." + output_file)
        print("Writing output to: k_end." + output_file)
        with open(input_file, encoding="utf-8", errors="ignore") as fp:
            line = True
            start_file_handler = open("k_start."+ output_file, "a+", encoding="utf-8", errors="ignore")
            mid_file_handler = open("k_mid."+ output_file, "a+", encoding="utf-8", errors="ignore")
            end_file_handler = open("k_end."+ output_file, "a+", encoding="utf-8", errors="ignore")
            while line:
                line = fp.readline()
                original_plaintext = line.rstrip("\n").rstrip("\r")
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

    elif end-start == max_length and end < len(input_word):
        next_start = start+1
        next_end = end+1
        if end-start >= min_length:
            return_array[1].append(input_word[start:end])

    elif end-start == max_length and end == len(input_word):
        next_start = start+1
        next_end = end
        if end-start >= min_length:
            return_array[1].append(input_word[start:end])

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
        # First section
        next_start = start+1
        next_end = end
        if end-start >= min_length:
            return_array[2].append(input_word[start:end])
    # Middle
    return kgramify_process(return_array, input_word, next_start, next_end, min_length, max_length)

def cgramify(docopt_args):
    input_file = docopt_args['<input_file>']
    output_file = docopt_args['<output_file>']
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    uppercase = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numeric = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    special = ['!', '"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ';', '<', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '+', ' ']
    special_full = ['!', '"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ';', '<', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '+', ' ', '\'', '-']
    # does not include ' and - because of their common use in normal language

    if ARGS.get('--min-length') is None:
        min_length = 4
    else:
        min_length = int(docopt_args.get('--min-length'))


    if ARGS.get('--max-length') is None:
        max_length = 32
    else:
        max_length = int(docopt_args.get('--max-length'))

    if ARGS.get('--filter') is None:
        output_filter = []
    else:
        output_filter = docopt_args.get('--filter')
        output_filter = output_filter.split(",")
        for item in output_filter:  # using this more complex filter to allow for more complex filters in the future such as startmidstartend
            original_item = item
            has_start = False  # prevent startstart or startmidstart
            has_mid = False
            has_end = False
            if item == "solo": continue
            while(len(item) > 0):
                match = False
                if item.startswith("start"):
                    match = True
                    if has_start:
                        break
                    has_start = True
                    item = item[len("start"):]
                if item.startswith("mid"):
                    match =  True
                    if has_mid:
                        break
                    has_mid = True
                    item = item[len("mid"):]
                if item.startswith("end"):
                    match =  True
                    if has_end:
                        break
                    has_end = True
                    item = item[len("end"):]
                if not match:
                    break
            if(len(item) > 0):
                print("--filter value \"" + original_item + "\" is not a valid filter and must consist exclusively of solo, start, mid, and end, startmid, midend, startend")
                sys.exit()

    input_file_handler = open(input_file, "r", encoding="utf-8", errors="ignore")
    output_file_handler = open("c_" + output_file, "a+", encoding="utf-8", errors="ignore")
    print("Writing output to: c_" + output_file)

    output_filter_file_handler = {}
    for item in output_filter:
        output_filter_file_handler[item] = open("c_" + item + "_" + output_file, "a+", encoding="utf-8", errors="ignore")
        print("Writing filter output to: c_" + item + "_" + output_file)


    for line in input_file_handler:
        original_plaintext = line.rstrip("\n").rstrip("\r")
        last_charset = 'empty'
        character_buffer = []
        matches = []
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
            
            if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                output_file_handler.write("".join(character_buffer) + "\n")
                matches.append("".join(character_buffer))
                


                if(current_charset == 'lowercase' or current_charset == 'uppercase'): current_charset = 'mixedcase'
            last_charset = current_charset
            character_buffer = [char]

        if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
            output_file_handler.write("".join(character_buffer) + "\n")
            matches.append("".join(character_buffer))

        # Output matches into filter outputs
        for filter_item in output_filter:
            filter_output = []
            if(filter_item == "solo" and len(matches) == 1):
                output_filter_file_handler[filter_item].write(matches[0] + "\n")
                continue
            if len(matches) < 2: continue

            if(filter_item == "start"):
                filter_output = [matches[0]]
            if(filter_item == "end"):
                filter_output = [matches[-1]]
            if(filter_item == "startend"):
                filter_output = [matches[0], matches[-1]]

            if len(matches) < 3: continue
            if(filter_item == "mid"):
                filter_output = matches[1:-1]
            if(filter_item == "startmid"):
                filter_output = matches[:-1]
            if(filter_item == "midend"):
                filter_output = matches[1:]
                
            for item in filter_output:
                output_filter_file_handler[filter_item].write(item)
            if len(filter_output) > 0:
                output_filter_file_handler[filter_item].write("\n")

        if ARGS.get('--mixed'):
            # Mixed case + less strict special check
            i = 0
            matches = []
            for char in original_plaintext:
                if i == 0: 
                    char = strtolower(char)
                    i += 1
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
                    if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                        output_file_handler.write("".join(character_buffer) + "\n")
                        matches.append("".join(character_buffer))
                    last_charset = current_charset
                    character_buffer = [char]
            if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                output_file_handler.write("".join(character_buffer) + "\n")
                matches.append("".join(character_buffer))

            for filter_item in output_filter:
                filter_output = []
                if(filter_item == "solo" and len(matches) == 1):
                    output_filter_file_handler[filter_item].write(matches[0] + "\n")
                    continue
                if len(matches) < 2: continue

                if(filter_item == "start"):
                    filter_output = [matches[0]]
                if(filter_item == "end"):
                    filter_output = [matches[-1]]
                if(filter_item == "startend"):
                    filter_output = [matches[0], matches[-1]]

                if len(matches) < 3: continue
                if(filter_item == "mid"):
                    filter_output = matches[1:-1]
                if(filter_item == "startmid"):
                    filter_output = matches[:-1]
                if(filter_item == "midend"):
                    filter_output = matches[1:]
                    
                for item in filter_output:
                    output_filter_file_handler[filter_item].write(item)
                if len(filter_output) > 0:
                    output_filter_file_handler[filter_item].write("\n")

            matches = []
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
                    if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                        output_file_handler.write("".join(character_buffer) + "\n")
                        matches.append("".join(character_buffer))
                    last_charset = current_charset
                    character_buffer = [char]

            if len(character_buffer) >= min_length and len(character_buffer) <= max_length:
                output_file_handler.write("".join(character_buffer) + "\n")
                matches.append("".join(character_buffer))

            for filter_item in output_filter:
                filter_output = []
                if(filter_item == "solo" and len(matches) == 1):
                    output_filter_file_handler[filter_item].write(matches[0] + "\n")
                    continue
                if len(matches) < 2: continue

                if(filter_item == "start"):
                    filter_output = [matches[0]]
                if(filter_item == "end"):
                    filter_output = [matches[-1]]
                if(filter_item == "startend"):
                    filter_output = [matches[0], matches[-1]]

                if len(matches) < 3: continue
                if(filter_item == "mid"):
                    filter_output = matches[1:-1]
                if(filter_item == "startmid"):
                    filter_output = matches[:-1]
                if(filter_item == "midend"):
                    filter_output = matches[1:]
                    
                for item in filter_output:
                    output_filter_file_handler[filter_item].write(item)
                if len(filter_output) > 0:
                    output_filter_file_handler[filter_item].write("\n")

    input_file_handler.close()
    output_file_handler.close()
    for filter_item in output_filter:
        output_filter_file_handler[filter_item].close()

if __name__ == '__main__':
    ARGS = docopt(__doc__, version='2.3')
    if not os.path.exists(ARGS.get('<input_file>')):
        print("Input file does not exist.")
        sys.exit()

    if ARGS.get('--min-length') is not None and int(ARGS.get('--min-length')) < 0:
        print("Min Length should be greater than 0.")
        sys.exit()

    if ARGS.get('--max-length') is not None and int(ARGS.get('--max-length', 1)) < 0:
        print("Max Length should be greater than 0.")
        sys.exit()

    if ARGS.get('--min-length') is not None and ARGS.get('--max-length') is not None:
        if int(ARGS.get('--min-length')) > int(ARGS.get('--max-length')):
            print("Min Length should be smaller or equal to Max length.")
            exit()

    if ARGS.get('word'):
        ngramify(ARGS)

    if ARGS.get('character'):
        kgramify(ARGS)

    if ARGS.get('charset'):
        cgramify(ARGS)
    print()
    print("Don't forget to de-duplicate and sort the output.\nRecommended command:")
    print("cat output_file.txt | sort | uniq -c | sort -rn | grep -oP '^ *[0-9]+ \\K.*' > sorted_output.txt")
