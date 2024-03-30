# crapcrypt
A simple symmetric encryption algorithm written in bad C.

# Usage
`./main -m mode -i input_file -o output_file -p password [-d]`

-m flag tells the program which encryption mode to use, choices are: [ecb, cbc]

-d flag tells the program to decrypt the ciphertext read from the input file instead of encrypting it.
