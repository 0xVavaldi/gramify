# Gramify

Gramify is an analysis tool built with the purpose of enhancing attacks on complex passwords through the use of n-grams.
Gramify offers three types of n-gram analysis
- Word
- Character
- Charset

These each perform n-grams at their respective levels.

## Installation
```
pip install -r requirements.txt
```
`docopt` is required. `tqdm` is optional and only used for the progress bar.

## Common options
These work in every mode:
- `<input_file>` can be `-` to read from STDIN. Lines written in `$HEX[...]` notation are decoded first.
- `<output_file>` is a base name: every output gets a prefix on the file name, so `out/list.txt` becomes `out/k_rolling.list.txt`.
- `--stdout` prints to STDOUT instead of writing a file (not possible when a mode writes several files: character mode without `--rolling`, or charset mode with `--filter`).
- `--count` de-duplicates in memory and writes the output sorted by frequency, most common first. `--min-count=<int>` also drops grams seen fewer than `<int>` times. This replaces the `sort | uniq -c | sort -rn` step but needs enough RAM to hold every unique gram.
- `--append` adds to existing output files. Without it, existing output files are overwritten.
- `--quiet` hides the progress bar and status messages. These are written to STDERR, so they never end up in `--stdout` output.

Grams that contain control characters (or start with `$HEX[`) are written in `$HEX[...]` notation, which hashcat reads natively. Bytes that are not valid UTF-8 are written back unchanged. Lines end at `\n` (trailing `\r` characters are removed), the same as hashcat; a lone `\r` inside a line is kept as part of it.

## What is an n-gram?
Those unfamiliar with the term will most easily understand it as the n words that follow each other naturally. At a word level the sentence: "I am writing a program" can be split at 2-gram level into: `["I am", "am writing", "writing a", "a program"]`. at 3-gram level into: `["I am writing", "am writing a", "writing a program"]`. This can also be done at a character level for example with "abc defg" into the 3-gram `["abc", "bc ", "c d", " de", "def", "efg"]`. Logically you can imagine that using this on books, or song lyrics can turn into a powerful analytical form where you can extract quotes or find words commonly used together such as the words: "I am", "He is" instead of: "capricorn icecream".

## Word n-grams
The options offered by gramify are as follows:

```gramify.py word <input_file> (<output_file> | --stdout) [--min-length=<int>] [--max-length=<int>] [--ngram-more] [--per-line]```
--min-length refers to the minimum amount of words that ngrams should be. Ergo. at least `<int>` words (Default: 1)
--max-length refers to the maximum amount of words that ngrams should be. Ergo. at most `<int>` words (Default: 10)
--ngram-more adds the same n-grams again with special characters removed from each word, and once more in lowercase
--per-line stops n-grams from running across line boundaries. By default the input is treated as one running text (books, lyrics); use --per-line for a list of passphrases.

The output file is called `n_<output_file>`.

Expecting long quotes or lyrics? Increase the --max-length, the penalty is often minor.

Example of input file format:
```
But now that I'm home feels like I'm in heaven
See I been travelin'
Ooh, whoah ooh whoah
I'm in heaven
Oh and I'm, feeling right at home
Feeling right at home
Feeling like I'm in heaven
It's like I'm in heaven
It's like I'm in heaven, ooh we oh
```

Output is unsorted data containing duplicates like the word "It's" and "I'm" as 1-gram or "I'm in heaven" as 3-gram.
Sorting them as recommended (sort by occurrence) will put the best at the top, so you can HEAD the output file if the data is too much.
Read more: https://en.wikipedia.org/wiki/N-gram

Some recommended commands would be:
```
gramify.py word <input_file> <output_file> 
gramify.py word <input_file> <output_file> --max-length=32

hashcat -a0 -m0 <hashlist> <output_file> -r <sentence_mangling_rules>
hashcat -a1 -m0 <hashlist> <output_file> <output_file> -j"$ "
```

## Character n-grams (k-grams)
The options offered by gramify are as follows:

```gramify.py character <input_file> (<output_file> | --stdout) [--min-length=<int>] [--max-length=<int>] [--rolling]```
--min-length refers to the minimum amount of characters that ngrams should be. Ergo. at least `<int>` characters (Default: 3)
--max-length refers to the maximum amount of characters that ngrams should be. Ergo. at most `<int>` characters (Default: 8, or 32 if rolling)
--rolling explained later

k-grams or character-based n-grams are great for analyzing what passwords start or end with. Therefore it is split up into three files: `k_start.<output_file>`, `k_mid.<output_file>` and `k_end.<output_file>`.
The k_start file is ideal with hashcat -a6 using it as the input dictionary with mask appended to it
On the opposite end is the k_end file which is great with hashcat -a7 using it as the end of the word with a mask prepended to it.
Additionally you can use the start, mid and end files in any combination using -a1 or combinatorX.exe (from hashcat-utils) to combine them back together in any combination available, resulting in probable passwords.

For a line of length L:
- k_start contains every prefix of --min-length up to --max-length characters, but never the whole line: `^.{3,8}` by default, capped at L-1 characters.
- k_end contains every suffix of --min-length up to --max-length characters, but never the whole line: `.{3,8}$` by default, capped at L-1 characters.
- k_mid contains every substring of exactly --max-length characters (only for lines longer than --max-length).
- Lines of --min-length characters or fewer produce nothing.

For example `password12` with the defaults gives `pas` ... `password` in k_start, `password`, `assword1` and `ssword12` in k_mid, and `ssword12` ... `d12` in k_end.

--rolling addresses some of the limitations this has. The benefit of having them split is that you have 3 different parts that each have a specific function. But sometimes you're not looking for the specific start, mid, end but more the classic k-gram as specified before. This would be it. It produces one file that has character-based ngram for all lengths.


Some recommended commands would be:
```
gramify.py character <input_file> <output_file> 
gramify.py character <input_file> <output_file> --max-length=128           (this would essentially empty out the k_mid file.
gramify.py character <input_file> <output_file> --rolling
gramify.py character <input_file> <output_file> --rolling --min-count=5    (keep only k-grams seen 5 times or more, most common first)

hashcat -a0 -m0 <hashlist> k_start.<output_file> k_mid.<output_file> k_end.<output_file> -r <popular rules>
hashcat -a0 -m0 <hashlist> k_start.<output_file> k_mid.<output_file> k_end.<output_file> -r <top_1500.rule> -r <top_1500.rule>
hashcat -a6 -m0 <hashlist> k_start.<output_file> ?a?a?a?a -i
hashcat -a7 -m0 <hashlist> ?a?a?a?a k_end.<output_file> -i
hashcat -a1 -m0 <hashlist> k_start.<output_file> k_mid.<output_file>
hashcat -a1 -m0 <hashlist> k_start.<output_file> k_end.<output_file>
hashcat -a1 -m0 <hashlist> k_mid.<output_file> k_start.<output_file>
hashcat -a1 -m0 <hashlist> k_mid.<output_file> k_end.<output_file>
hashcat -a1 -m0 <hashlist> k_end.<output_file> k_start.<output_file>
hashcat -a1 -m0 <hashlist> k_end.<output_file> k_mid.<output_file>
```
Read more: https://nlp.stanford.edu/IR-book/html/htmledition/k-gram-indexes-for-wildcard-queries-1.html

## Charset n-grams
`gramify.py charset <input_file> (<output_file> | --stdout) [--min-length=<int>] [--max-length=<int>] [--mixed] [--filter=<str>] [--filter-combo-length=<int>] [--cgram-rulify-beta]`

--min-length refers to the minimum amount of characters that each word should have. Ergo. at least `<int>` characters (Default: 3)
--max-length refers to the maximum amount of characters that each word should have. Ergo. at most `<int>` characters (Default: 32)
--mixed do not make a distinction between upper and lowercase or upper, lowercase and numeric in two different passes
--filter make use of the start, mid and end filters to combine and only grab the first element, mid elements, or last element. Each filter is written to `c_<filter>_<output_file>`.
--filter-combo-length [BETA] adds every combination of start, mid and end up to `<int>` parts as filters (for example 2 adds start, mid, end, startmid, startend, midstart, ...).
--cgram-rulify-beta [BETA] also writes each filter as hashcat rules to `c_<filter>_<output_file>.rule`: start becomes `^` (prepend), end becomes `$` (append) and mid becomes `i` (insert) and `o` (overwrite) rules. Characters outside printable ASCII are written as `\xHH`, and rules that do not fit hashcat's limits (31 functions, 255 characters, insert/overwrite positions up to `Z`) are skipped.

The main output file is called `c_<output_file>`.


This type of n-gram is more focused on character set boundries. Moving from UPPERCASE to lowercase. From Digits to lowercase or vice versa. This way you're able to take the passwords (using --min-length=4):
```
password123456 -> [password, 123456]
PASSword123123magicman -> [PASS, word, 123123, magicman]
THEBESTINTHEWORLD54321 -> [THEBESTINTHEWORLD, 54321]
there are a lot of things to say -> [there, things]
```
This can be great for extracting words or common patterns out of passwords, removing punctuation or discovering common themes. From here on we can use rules on our newly discovered words to find new passwords. Gramify builds on this concept by allowing an Uppercase character to go to a lowercase character, but only if it's the first in the word allowing the capture of items like `PassWord123456 -> [Pass, Word, 123456]`.

An example of --filter using the above examples and the following available filters: solo, start, mid, and end, startmid, midend, startend:
```
python3 gramify.py charset hashmob.net_2022-07-03.found test.txt --filter 'duo,duostart,duoend,start,mid,end,startmid,midend'

password123456 will be converted into [password, 123456]. That is two elements, so it only shows up in the duo filters:
password => duostart
password123456 => duo
123456 => duoend

PASSword123123magicman will be converted into [PASS, word, 123123, magicman] which will have:
PASS => start
word123123 => mid
magicman => end
PASSword123123 => startmid
word123123magicman => midend

password will be converted into [password]: which falls under 'solo' and therefore isn't written to a file as it's not part of our filters.
```
The elements are the charset parts that pass --min-length and --max-length, so use `--min-length=1` when you filter on mid: otherwise short parts such as a single `!` disappear and the remaining parts shift into different positions.

If you want even more options: using the --mixed will help with short words with many upper and lowercase like:
```
PaSSwOrd123123 -> [PaSSwOrd, 123123]
```
These will come in addition to the other passwords. Current settings do not allow for exclusive mixed generation.

## Sorting the output
Without `--count` the output is unsorted and contains duplicates. Gramify prints a recommended command for each file it wrote, for example:
```
LC_ALL=C sort "k_rolling.list.txt" | uniq -c | LC_ALL=C sort -rn | awk '$1 >= 5' | sed -E 's/^ *[0-9]+ //' > "k_rolling.list.txt.sorted"
```
This keeps grams seen at least 5 times, most common first. The same works in a pipeline, or let gramify do it with `--min-count=5`:
```
cat wordlist.txt | python3 gramify.py character - --stdout --rolling | sort | uniq -c | sort -rn | awk '$1 >= 5' | sed -E 's/^ *[0-9]+ //' > kgrams.txt
python3 gramify.py character wordlist.txt --stdout --rolling --min-count=5 > kgrams.txt
python3 gramify.py charset hashmob.found --stdout --min-length=4 | sort -u | hashcat -m0 hashes.txt -r best64.rule
```

Inspired by: https://github.com/hops/pack2 (https://github.com/hops/pack2/blob/master/src/cgrams.rs)
