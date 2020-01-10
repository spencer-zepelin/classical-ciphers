Applied Cryptography
MPCS 56530

Project 1
Classical Cipher Implementations

Spencer Zepelin

October 13, 2019

------------------


Building and Running the Program
---

The classical encryption utility was written in Python 3 and should run 
in any environment with Python 3 installed as it depends only on the 
standard library.

The program should be run off the command line as follows:

	python classical.py <MODE> <KEY>

If 'python' does not point to a Python 3 installation in the user's PATH 
variable, the filepath to the installation can replace 'python' in the 
above.

The utility supports text encryption through both the Vigenere and 
Playfair ciphers through the following four options for <MODE>:

	vencrypt
	vdecrypt
	pencrypt
	pdecrypt

As one might surmise, 'vencrypt' and 'vdecrypt' perform Vigenere 
encryption and decryption, respectively, while 'pencrypt' and 'pdecrypt' 
perform those operations using the Playfair cipher instead.

All operations read input from STDIN and write input to STDOUT. For 
encryption inputs, only lowercase letters will be considered with all 
other characters disregarded. For decryption inputs, only uppercase 
letters will be considered with all other characters disregarded. The key 
must contain only letters, but the case of those letters is irrelevant. 
As such, the following two keys...

	ChIcAgO 
	chicago

...will be regarded as the same. Additionally, as an artifact of the 
Playfair algorithm, keys with repeated letters will yield the same result 
as that key with no repeats so long as the first occurence of each letter 
is in the same order. For instance, the following keys...

	crypto
	crrrryptoooo
	crycccccccccccccptppppppo

...will yield the same result. Within the context of the Playfair cipher, 
'i' and 'j' are treated as identical letters. As such, Playfair-encrypted 
ciphertext will not contain the character 'I', and Playfair-decrypted 
ciphertext will contain the character 'j' everywhere an 'i' should 
appear. Playfair ciphertext may be longer than the plaintext input and 
Playfair-decrypted plaintext may contain seemingly aberrant 'x' 
characters added to ensure all digrams were even and internally 
non-identical. In the unlikely event that a digram is 'xx' or a lone 'x' 
at the end of the message, a 'z' is added instead of an 'x'.

Encryption will yield uppercase cipher text while decryption will yield 
lowercase plaintext.


Testing

---

The program will read through any input off of STDIN for bytes it can 
recognize as text. Testing was performed primarily using the 'cat' and 
'echo' tools. The program passed all tests on the developer's machine and 
the UChicago departmental Linux cluster, including inputs of zero length 
and those greater than the size of the machine's memory. Output from an 
encryption function can be piped as input directly to a decryption 
function. If no standard input is available, a standard bash shell will 
enter interactive mode where it will wait for text and process whatever 
text is entered after pressing <ctrl-d> one or two times.


Program Design 
---

The program ensures inputs are correct and passes off control to a 
separate function for each mode of operation. All modes read chunks of 
up to one KB of data at a time and flush out STDOUT afterwards to ensure 
the program avoids eating up all system memory. 

It is possible that the text chunking could result in a dangling 
character during Playfair encryption resulting in an additional filler 
('x' or 'z') being added between chunks. As this is unlikely to 
interfere with the interpretation of the deciphered plaintext, it is 
considered an acceptable trade-off to protect system memory.

Vigenere encryption and decryption rely on simple numeric manipulation 
of ASCII values. Playfair operations, however, have their own class to 
support processing and specialized helper functions to clean inputs. The 
Playfair functions begin by building the Playfair table as two inverse 
hash tables to which digrams are then passed for encryption and 
decryption. Assertion statements on decryption ensure that Playfair 
ciphertext is valid.