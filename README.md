# pbkdf_pass_runner
Runs through a word list and tries all entries as passwords with a given salt for an [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) SHA-1 implementation, checking if they generate a matching given key.

Note that this was written for a specific purpose, and is not designed to be a tried-and-tested tool. I also make no guarantees of it's speed, though it should be able to leverage multi-core systems fairly well.

## Usage
```
pbkdf_pass_runner.exe <num_threads> <salt (hex string)> <iterations = 20> <compare_key (hex string)> <delimiter = 0a> <word_list_path>
```
The word list needs to have one word/password per line.
