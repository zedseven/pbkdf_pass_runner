# pbkdf_pass_runner
Runs through a word list and tries all entries as passwords with a given salt for an AES PBKDF2 SHA-1 implementation, checking if they generate a matching given key.

## Usage
```
pbkdf_pass_runner.exe <num_threads> <salt (hex string)> <iterations = 20> <compare_key (hex string)> <word_list_path>
```
The word list needs to have one word/password per line.
