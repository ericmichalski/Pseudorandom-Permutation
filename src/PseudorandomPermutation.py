import random
import sys
from itertools import permutations
from itertools import product
import copy

# Formats the output by removing , [ ] and adding spaces if requested
def formatOutput(inStr, space=False):
	if (space):
		newStr = str(inStr).replace(',','').replace(' ','').replace('[','').replace(']',' ')
	else:
		newStr = str(inStr).replace(',','').replace(' ','').replace('[','').replace(']','')
	return newStr

# Generates all binary strings with a length n
def generateAllBinaryStrings(n, arr, i, groups):
	if i == n:
		groups.append(copy.copy(arr))
		return
	elif i < n:
		arr[i] = 0
		generateAllBinaryStrings(n, arr, i + 1, groups)
	
		arr[i] = 1
		generateAllBinaryStrings(n, arr, i + 1, groups)

#  Generates permutations for a permutation family and writes it to the default text file: ../data/permutations.txt
def permFamily(n=2, pm="../data/permutations.txt"):
	arr = [None] * int(n)
	groups = [] # Stores the generated binary strings in a list (Total length will be 2^n)
	generateAllBinaryStrings(int(n), arr, 0, groups)

	# Open given file
	permFile = open(pm, "w")

	# Prints/Writes the paired values onto a line 
	print("   d", end="	 ")
	permFile.write("   d	 ")
	for each in groups:
		print(formatOutput(each), end=" ")
		permFile.write(formatOutput(each) + " ")
	print('\n', end="")
	permFile.write("\n")

	# Creates the permutations using the set of groups and prints/writes each onto a line. The length of the permutations will be groups! (or the factorial of the length of the list "groups")
	perms = permutations(groups)
	count = 1
	for perm in perms:
		print(" f" + str(count) + "(d)", end="	 ")
		print(formatOutput(str(perm)[1:-1], True))
		permFile.write(" f" + str(count) + "(d)" + "	 " + formatOutput(str(perm)[1:-1], True) + "\n")
		count = count + 1

	permFile.close()
	return

#  Generates permutations for a pseudorandom permutation and writes it to the default text file: ../data/pseudopermutations.txt
def prpGen(n=4, l=4, pm="../data/pseudopermutations.txt"):
	arr = [None] * int(n)
	arr2 = [None] * int(l)
	groupsD = []
	groupsK = []
	generateAllBinaryStrings(int(n), arr, 0, groupsD)
	generateAllBinaryStrings(int(l), arr2, 0, groupsK)

	# Open given file
	pseudoPermFile = open(pm, "w")

	# Generate random IV
	iv = ""
	for i in range(int(l)):
		iv = iv + str(random.randint(0, 1))
	print("Random IV: " + iv)
	pseudoPermFile.write("Random IV: " + iv + '\n')

	# Prints/Writes the paired values onto a line 
	print("	 d", end="	 ")
	pseudoPermFile.write("	 d	 ")
	dValues = []
	for each in groupsD:
		dValues.append(formatOutput(each))
		print(formatOutput(each), end=" ")
		pseudoPermFile.write(formatOutput(each) + " ")
	print('\n')
	pseudoPermFile.write("\n")

	# Creates all the key values
	kValues = []
	for each in groupsK:
		kValues.append(formatOutput(each))

	# Creates the permutations using the set of groups and prints/writes each onto a line. The length of the permutations will be groups! (or the factorial of the length of the list "groups")
	perms = permutations(groupsD)
	count = 0

	# Loop through the permutations and write it to a file
	for perm in perms:
		print("k=" + kValues[count] + ", f" + str(count) + "(d)", end="	 ")
		print(formatOutput(str(perm)[1:-1], True))
		pseudoPermFile.write("k=" + kValues[count] + ", f" + str(count) + "(d)" + "	 " + formatOutput(str(perm)[1:-1], True) + "\n")

		# Increase count and check if the count is greater than the desired matrix size
		count = count + 1
		if (count >= int(l)*int(n)):
			break

	pseudoPermFile.close()
	return

# Encrypt a message using CBC mode
def EncCBC(m=100111000011, l=4, k=1100, pm="../data/pseudopermutations.txt", ct="../data/ciphertext.txt"):
	m = int(m)
	l = int(l)
	k = int(k)
	permTable = [] # Create empty double list to hold the values of the generated table
	for x in range(0,l*l):
		permTable.append([])
	
	permFile = open(pm, "r")
	Lines = permFile.readlines()
	c = 0
	kValues = []
	# Retrieves each line of the permutation table and splits the rows into a list of lists (permTable)
	for line in Lines:
		if (c == 0):
			inputIV = line.strip().split()
			inputIV.pop(0)
			inputIV.pop(0)
		elif (c == 1):
			dValues = line.strip().split()
			dValues.pop(0)
		else:
			inputKVs = line.strip().split()
			kValues.append((str(inputKVs[0])[2:])[:-1]) # Get Key Values and make a separate list for them
			inputKVs.pop(0)
			inputKVs.pop(0)
			permTable[c-2].append(inputKVs) # Append function table values into a list of lists
		c += 1
	permFile.close()

	startNum = 0
	endNum = 4
	newMList = []
	# Separate message into l lengths
	for i in range(0,int(len(str(m))/l)):
		newMList.append(str(m)[startNum:endNum])
		startNum = startNum + l
		endNum = startNum + l
	print("Message list:", newMList)

	count = 0
	prevmIVText = ""
	mIVText = []
	for x in newMList:
		# If first chunk in message, use IV, otherwise use previous cipher
		if (count == 0):
			iv = inputIV[0]
		else:
			iv = prevmIVText

		# Generate an XOR of the input message and IV or input message and the previous cipher
		y=int(x,2) ^ int(iv,2)
		mIVText.append('{0:0{1}b}'.format(y,len(x)))
		prevmIVText = '{0:0{1}b}'.format(y,len(x))
		count = count + 1
	print("XOR list:", mIVText)

	# Find the correct key row
	for row in kValues:
		if (str(k) == row):
			curRow = permTable[kValues.index(row)]
	cipherText = ""

	# For each message chunk, find the correct d column and data point to add to the ciphertexts
	for i in range(len(mIVText)):
		for col in dValues:
			if (str(mIVText[i]) == col):
				cipherText = cipherText + curRow[0][dValues.index(col)]

	# Print ciphertext to terminal and write to file
	print("Ciphertext:", cipherText)
	cipherFile = open(ct, "w")
	cipherFile.write(cipherText)
	cipherFile.close()

# Decrypt a message using CBC mode
def DecCBC(l=4, k=1100, pm="../data/pseudopermutations.txt", ct="../data/ciphertext.txt"):
	l = int(l)
	k = int(k)
	permTable = [] # Create empty double list to hold the values of the generated table
	for x in range(0,l*l):
		permTable.append([])
	
	permFile = open(pm, "r")
	Lines = permFile.readlines()
	c = 0
	# Retrieves each line of the permutation table and splits the rows into a list of lists (permTable)
	kValues = []
	for line in Lines:
		if (c == 0):
			inputIV = line.strip().split()
			inputIV.pop(0)
			inputIV.pop(0)
		elif (c == 1):
			dValues = line.strip().split()
			dValues.pop(0)
		else:
			inputKVs = line.strip().split()
			kValues.append((str(inputKVs[0])[2:])[:-1]) # Get Key Values and make a separate list for them
			inputKVs.pop(0)
			inputKVs.pop(0)
			permTable[c-2].append(inputKVs) # Append function table values into a list of lists
		c += 1
	permFile.close()

	# Get ciphertext
	cipherFile = open(ct, "r")
	cipherText = cipherFile.read()
	cipherFile.close()

	startNum = 0
	endNum = 4
	newCList = []
	# Separate ciphertext into l lengths
	for i in range(0,int(len(str(cipherText))/l)):
		newCList.append(str(cipherText)[startNum:endNum])
		startNum = startNum + l
		endNum = startNum + l
	print("Cipher list:", newCList)

	# Find the correct key row
	for row in kValues:
		if (str(k) == row):
			curRow = permTable[kValues.index(row)]

	newDValues = []
	# For each ciphertext chunk, find the associated function table d value
	for el in newCList:
		for i in curRow[0]:
			if (el == i):
				newDValues.append(dValues[curRow[0].index(i)])
	print("Function values:", newDValues)
	
	count = 0
	prevCText = ""
	messageText = []
	iv = ""
	for x in newDValues:
		# If first chunk in message, use IV, otherwise use previous message output
		if (count == 0):
			iv = inputIV[0]
		else:
			iv = prevCText
		# Generate an XOR of the ciphertext and IV or ciphertext and the previous message output
		y=int(x,2) ^ int(iv,2)
		messageText.append('{0:0{1}b}'.format(y,len(x)))
		prevCText = newCList[count]
		count = count + 1

	# Print the decrypted message
	print("Message list:", messageText)
	print("Final message output: ", end="")
	for each in messageText:
		print(each, end="")
	print('')


# Input checks
if len(sys.argv) > 1:
	if sys.argv[1] == "EncCBC":
		if len(sys.argv) > 6:
			EncCBC(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
		else:
			print("Not enough arguments, using default values")
			EncCBC()
	elif sys.argv[1] == "DecCBC":
		if len(sys.argv) > 5:
			DecCBC(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
		else:
			print("Not enough arguments, using default values")
			DecCBC()
	elif sys.argv[1] == "permFamily":
		if len(sys.argv) > 3:
			permFamily(sys.argv[2], sys.argv[3])
		else:
			print("Not enough arguments, using default values")
			permFamily()
	elif sys.argv[1] == "prpGen":
		if len(sys.argv) > 4:
			prpGen(sys.argv[2], sys.argv[3], sys.argv[4])
		else:
			print("Not enough arguments, using default values")
			prpGen()
else:
	print("Using default values")
	# Runs all the default functions
	permFamily()
	prpGen()
	EncCBC()
	DecCBC()