"""
Generates a fake password file of all 8 char passwords

"""

import string
import random
def id_generator(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
	return ''.join(random.choice(chars) for _ in range(size))+"\n"

with open("generated_tiny.txt", "w") as output_file:
	for i in range(40000):
		output_file.write(id_generator(8))
