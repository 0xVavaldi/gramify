# Gramify

Gramify is an analysis tool built with the purpose of enhancing attacks on complex passwords through the use of n-grams.
Gramify offers three types of n-gram analysis
- Word
- Character
- Charset

These each perform n-grams at their respective levels.

## What is an n-gram?
Those unfamiliar with the term will most easily understand it as the n words that follow each other naturally. At a word level the sentence: "I am writing a program" can be split at 2-gram level into: `["I am", "am writing", "writing a", "a program"]`. at 3-gram level into: `["I am writing", "am writing a", "writing a program"]`. This can also be done at a character level for example with "abc defg" into the 3-gram `["abc", "bc ", "c d", " de", "def", "efg"]`. Logically you can imagine that using this on books, or song lyrics can turn into a powerful analytical form where you can extract quotes or find words commonly used together such as the words: "I am", "He is" instead of: "capricorn icecream".

## Word n-grams
The options offered by the gramify as of version 0.8 are as follows:

```gramify.py word <input_file> <output_file> [--min-length=<int>] [--max-length=<int>]```
--min-length refers to the minimum amount of words that ngrams should be. Ergo. at least <int> words (Default: 1)
--max-length refers to the maximum amount of words that ngrams should be. Ergo. at least <int> words (Default: 10)

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
Read more: https://nlp.stanford.edu/IR-book/html/htmledition/k-gram-indexes-for-wildcard-queries-1.html

Some recommended commands would be:
```
gramify.py word <input_file> <output_file> 
gramify.py word <input_file> <output_file> --max-length=32
```

## Character n-grams (k-grams)
The options offered by the gramify as of version 0.8 are as follows:

```gramify.py character <input_file> <output_file> [--min-length=<int>] [--max-length=<int>] [--rolling]```
--min-length refers to the minimum amount of characters that ngrams should be. Ergo. at least <int> characters (Default: 4)
--max-length refers to the maximum amount of characters that ngrams should be. Ergo. at least <int> characters (Default: 8, or 32 if rolling)
--rolling explained later

k-grams or character-based n-grams are great for analyzing what passwords start or end with. Therefore it is split up into start_ mid_ and end_.
The start_ is ideal with hashcat -a6 using it as the input dictionary with mask appended to it
On the opposite end is the end_ which is great with hashcat -a7 using it as the end of the word with a mask prepended to it.
Additionally you can use start_, mid_ and end_ in any combination using -a1 or combinatorX.exe (from hashcat-utils) to combine them back together in any combination available, resulting in probable passwords.

The start_ will contain `^.{--min-length, --max-length}` or everything from the start of the line until everything between --min-length and --max-length.
By default this would be the regex: `^.{4,8}`

The end_ will contain `.{--min-length, --max-length}$` or everything from the start of the line until everything between --min-length and --max-length.
By default this would be the regex: `.{4,8}$`

The mid_ section will contain the remainder of whatever is availabe: Seeing start_, mid_ and end_ as separate regex groups you could represent it as this: `^(.{--min-length, --max-length})(.*?)(.{--min-length, --max-length}$)`

--rolling addresses some of the limitations this has. The benefit of having them split is that you have 3 different parts that each have a specific function. But sometimes you're not looking for the specific start, mid, end but more the classic k-gram as specified before. This would be it. It produces one file that has character-based ngram for all lengths.


Some recommended commands would be:
```
gramify.py character <input_file> <output_file> 
gramify.py character <input_file> <output_file> --max-length=128           (this would essentially empty out the mid_ file.
gramify.py character <input_file> <output_file> --rolling
```
Read more: https://nlp.stanford.edu/IR-book/html/htmledition/k-gram-indexes-for-wildcard-queries-1.html

## Charset n-grams
`gramify.py charset <input_file> <output_file> [--min-length=<int>] [--max-length=<int>] [--mixed]`

--min-length refers to the minimum amount of characters that each word should have. Ergo. at least <int> characters (Default: 4)
--max-length refers to the minimum amount of characters that each word should have. Ergo. at least <int> characters (Default: 32)
--mixed do not make a distinction between upper and lowercase


This type of n-gram is more focused on character set boundries. Moving from UPPERCASE to lowercase. From Digits to lowercase or vice versa. This way you're able to take the passwords (assuming a default --min-length of 4):
```
password123456 -> [password, 123456]
PASSword123123magicman -> [PASS, word, 123123, magicman]
THEBESTINTHEWORLD54321 -> [THEBESTINTHEWORLD54321]
there are a lot of things to say -> [there, things]
```
This can be great for extracting words or common patterns out of passwords, removing punctuation or discovering common themes. From here on we can use rules on our newly discovered words to find new passwords. Gramify builds on this concept by allowing an Uppercase character to go to a lowercase character, but only if it's the first in the word allowing the capture of items like `PassWord123456 -> [Pass, Word, 123456]`.

If you want even more options, using the --mixed will help with short words with many upper and lowercase like:
```
PaSSwOrd123123 -> [PaSSwOrd, 123123]
```
