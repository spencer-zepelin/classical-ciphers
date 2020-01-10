import sys

############ MODE FUNCTIONS ##############

# Vigenere Encryption Function
def vig_enc(key):
	key_index = 0
	# Read a chunk of characters off stdin
	chunk = sys.stdin.read(1024)
	# Control for EOF
	while chunk:
		out_buff = ''
		# Loop through chars in chunk
		for letter in chunk:
			# Skip anything other than lowercase letters
			if letter.isalpha() and letter.islower():
				# Shift by key value 
				# 97 is ascii lowercase offset
				new_letter = ord(letter) + ord(key[key_index]) - 97
				# Add wraparound condition
				if new_letter > 122:
					new_letter -= 26
				# Change to upper case
				new_letter -= 32
				# Modularly increment key_index
				key_index = (key_index + 1) % len(key)
				# Add letter to out_buff
				out_buff = out_buff + chr(new_letter)
			else:
				pass
		# Write buffer to stdout and print to screen
		sys.stdout.write(out_buff)
		sys.stdout.flush()
		# Read in next chunk
		chunk = sys.stdin.read(1024)
	# Add line break at termination
	print('\n')
	return

# Vigenere Decryption Function
def vig_dec(key):
	key_index = 0
	# Read a chunk of characters off stdin
	chunk = sys.stdin.read(1024)
	# Control for EOF
	while chunk:
		out_buff = ''
		# Loop through chars in chunk
		for letter in chunk:
			# Skip anything other than uppercase letters
			if letter.isalpha() and letter.isupper():
				# Shift by key value 
				new_letter = ord(letter) - (ord(key[key_index]) - 97)
				# Wraparound conditions
				if new_letter < 65:
					new_letter += 26
				# Change to lower case
				new_letter += 32
				# Modularly increment key_index
				key_index = (key_index + 1) % len(key)
				# Add letter to out_buff
				out_buff = out_buff + chr(new_letter)
			else:
				pass
		# Write buffer to stdout and print to screen
		sys.stdout.write(out_buff)
		sys.stdout.flush()
		# Read in next chunk
		chunk = sys.stdin.read(1024)
	# Add line break at termination
	print('\n')
	return

# Playfair Encryption Function
def ply_enc(key):
	# Initialize Playfair object
	pf = Playfair(key)
	# Read in and clean a chunk
	chunk = clean_lower_string(sys.stdin.read(1024))
	# Control for EOF
	while chunk:
		out_buff = ''
		index = 0
		# Loop through full chunk
		while index < len(chunk):
			# First element of digram
			d1 = chunk[index]
			# Increment index
			index += 1
			# Pad if odd number and at end or duplicate letters
			# DO NOT INCREMENT INDEX
			if index == len(chunk) or chunk[index] == d1:
				# The edgiest of cases where the digram is 'xx' or there is a lone 'x' at the end
				if d1 == 'x':
					d2 = 'z'
				# Standard pad value
				else:
					d2 = 'x'
			else:
				# Take second element of digram
				d2 = chunk[index]
				# Increment index
				index += 1
			# Encrypt and write to out_buff
			out_buff += pf.encrypt(d1, d2)
		# Write buffer to stdout and print to screen
		sys.stdout.write(out_buff)
		sys.stdout.flush()
		# Read in next chunk
		chunk = clean_lower_string(sys.stdin.read(1024))
	# Add line break at termination
	print('\n')
	return

# Playfair Decryption Function
def ply_dec(key):
	# Initialize Playfair object
	pf = Playfair(key)
	# Read in and clean a chunk
	chunk = clean_upper_string(sys.stdin.read(1024))
	# Control for EOF
	while chunk:
		out_buff = ''
		index = 0
		# Assert condition for valid ciphertext
		assert len(chunk) % 2 == 0, 'Valid Playfair ciphertext should always be even in length'
		# Loop through full chunk
		while index < len(chunk):
			# First element of digram made lowercase
			d1 = chunk[index].lower()
			# Assert that digram elements not identical
			assert chunk[index + 1].lower() != d1, 'Valid Playfair ciphertext should never have identical chars in the same digram'
			# Second element of digram made lowercase
			d2 = chunk[index + 1].lower()
			# Index incremented by 2
			index += 2
			# Decrypt and write to out_buff
			out_buff += pf.decrypt(d1, d2)
		# Write buffer to stdout and print to screen
		sys.stdout.write(out_buff)
		sys.stdout.flush()
		# Read in next chunk
		chunk = clean_upper_string(sys.stdin.read(1024))
	# Add line break at termination
	print('\n')
	return
		

########## PLAYFAIR CLASS AND HELPER FUNCTIONS #############

# helper function to clean non-conforming plaintext inputs
def clean_lower_string(dirty_string):
	clean_string = ''
	for char in dirty_string:
		# Ignore everything except for lowercase letters
		if char.isalpha() and char.islower():
			# swap any 'i' for a 'j'
			if char == 'i':
				char = 'j'
			clean_string += char
	return clean_string

# helper function to clean non-conforming ciphertext inputs
def clean_upper_string(dirty_string):
	clean_string = ''
	for char in dirty_string:
		# Ignore everything except for uppercase letters
		if char.isalpha() and char.isupper():
			# Swap 'I' for 'J'
			if char == 'I':
				char == 'J'
			clean_string = clean_string + char
	return clean_string

# Class to support Playfair operations
class Playfair:
	# Playfair table generated on initialization
	# Structured as two mirror hash tables
	def __init__(self, key):
		used = ''
		row = 0
		column = 0
		# letter-keyed dict
		self.forward = {}
		# coord-keyed dict
		self.backward = {}
		# add all letters (except i)
		key = key + 'abcdefghjklmnopqrstuvwxyz'
		# loop through key then all of alphabet
		for letter in key:
			# replace any 'i' in key with a 'j'
			if letter == 'i':
				letter = 'j'
			# skip loop if letter already in data structure
			if letter in used:
				continue
			# add letter to hash tables
			else:
				self.forward[letter] = (row, column)
				self.backward[(row, column)] = letter
				# mark that the letter is now used
				used = used + letter
				# increment row if in last column
				if (column + 1) == 5:
					row += 1
				# modularly increment column
				column = (column + 1) % 5

	# Method for digraph encryption
	def encrypt(self, d1, d2):
		# pull coordinates from hash table
		d1_coords = self.forward[d1] 
		d2_coords = self.forward[d2]
		# If in same row
		if d1_coords[0] == d2_coords[0]:
			# select elements to the right of each
			d1out_coords = (d1_coords[0], (d1_coords[1] + 1) % 5)
			d2out_coords = (d1_coords[0], (d2_coords[1] + 1) % 5)
		# If in same column
		elif d1_coords[1] == d2_coords[1]:
			# select elements a row down from each
			d1out_coords = ((d1_coords[0] + 1) % 5, d1_coords[1])
			d2out_coords = ((d2_coords[0] + 1) % 5, d1_coords[1])
		# Neither same row or column--> same row, column of other
		else:
			d1out_coords = (d1_coords[0], d2_coords[1])
			d2out_coords = (d2_coords[0], d1_coords[1])
		# pull encrypted characters from reverse hash table
		d1out = self.backward[d1out_coords]
		d2out = self.backward[d2out_coords]
		# return capitalized digram
		return (d1out + d2out).upper()

	# Method for digraph decryption
	def decrypt(self, d1, d2):
		# pull coordinates from hash table
		d1_coords = self.forward[d1] 
		d2_coords = self.forward[d2]
		# If in same row
		if d1_coords[0] == d2_coords[0]:
			# select elements to the left of each
			d1out_coords = (d1_coords[0], (d1_coords[1] - 1) % 5)
			d2out_coords = (d1_coords[0], (d2_coords[1] - 1) % 5)
		# If in same column
		elif d1_coords[1] == d2_coords[1]:
			# select elements a row up from each
			d1out_coords = ((d1_coords[0] - 1) % 5, d1_coords[1])
			d2out_coords = ((d2_coords[0] - 1) % 5, d1_coords[1])
		# Neither same row or column--> same row, column of other
		else:
			d1out_coords = (d1_coords[0], d2_coords[1])
			d2out_coords = (d2_coords[0], d1_coords[1])
		# pull encrypted characters from reverse hash table
		d1out = self.backward[d1out_coords]
		d2out = self.backward[d2out_coords]
		# return lowercase digram
		return (d1out + d2out).lower()


######### COMMAND LINE CONTROL #############

if __name__ == '__main__':
	# Throw error and exit if improper number of arguments
	if len(sys.argv) != 3:
		sys.exit('\n---USAGE ERROR---\nCalls to the program should be of the form: \npython classical.py <MODE> <KEY>\n')
	# Pull mode and key off of command line
	mode = sys.argv[1]
	key = sys.argv[2]
	# Convert key to all lowercase
	if key.isalpha():
		key = key.lower()
	# Throw error if keys has non-letter characters
	else:
		sys.exit('\n---ERROR---\nKey must contain only letters, but "{}" was entered as key\n'.format(key))
	# Run main operation based on mode
	if mode == 'vencrypt':
		vig_enc(key)
	elif mode == 'vdecrypt':
		vig_dec(key)
	elif mode == 'pencrypt':
		ply_enc(key)
	elif mode == 'pdecrypt':
		ply_dec(key)
	# Throw error and exit if mode unrecognized
	else:
		sys.exit('\n---ERROR---\nMode "{}" does not match any recognized modes for this utility. Please use one of the following:\n  vencrypt\n  vdecrypt\n  pencrypt\n  pdecrypt\n'.format(mode))
	




