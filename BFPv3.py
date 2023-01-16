import glob
import hashlib
import os
import requests
import zipfile
import datetime
import sys

# get input directory, or use current directory if none is input
input_dir = input("Enter a directory (or leave blank for current directory): ")
if input_dir == "":
    input_dir = "."

# create the Breakfast_Potatoes directory if it doesn't exist
desktop_dir = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
breakfast_potatoes_dir = os.path.join(desktop_dir, "Breakfast_Potatoes")
if not os.path.exists(breakfast_potatoes_dir):
    os.makedirs(breakfast_potatoes_dir)

# get a list of all files in the input directory
files = [i for i in (os.path.join(input_dir, f) for f in os.listdir(input_dir)) if os.path.isfile(i)]

# create a dictionary of {file: hash} for all files
hashes = {}
for file in files:
    with open(file, "rb") as f:
        hashes[file] = hashlib.md5(f.read()).hexdigest()

# get the current date and time
now = datetime.datetime.now()

# create the file name for the hash list file
hashed_potatoes_filename = "Hashed_Potatoes_" + now.strftime("%Y%m%d-%H%M%S") + ".txt"
hashed_potatoes_filepath = os.path.join(breakfast_potatoes_dir, hashed_potatoes_filename)

# write the hashes to the Hashed_Potatoes file
with open(hashed_potatoes_filepath, 'w') as f:
    for file, hash in hashes.items():
        f.write(f"{file}: {hash}\n")

# find the Hashed_Potatoes file with the earliest datetime
hashed_potatoes_files = glob.glob(os.path.join(breakfast_potatoes_dir, "Hashed_Potatoes_*.txt"))
hashed_potatoes_files.sort()

# if there are no Hashed_Potatoes files, print "No existing reference file"
if len(hashed_potatoes_files) == 1:
    print("No existing reference file...A reference file was created")
    exit()

# if there are Hashed_Potatoes files, compare the hashes to the first one (which will be the earliest one)
else:
    # create a dictionary of {file: hash} for the first Hashed_Potatoes file
    old_hashes = {}
    with open(hashed_potatoes_files[0], 'r') as f:
        for line in f:
            file, hash = line.strip().split(": ")
            old_hashes[file] = hash
    # check for missing files
    mismatched_hashes = []
    for file in old_hashes:
        if file not in hashes:
            mismatched_hashes.append((file, old_hashes[file], None))
    # compare the old hashes to the new hashes and get a list of mismatched hashes
    for file, new_hash in hashes.items():
        old_hash = old_hashes.get(file)
        if old_hash is None or old_hash != new_hash:
            mismatched_hashes.append((file, old_hash, new_hash))

    # if there are no mismatched hashes, print "No changes found"
    if len(mismatched_hashes) == 0:
        print("No changes found")

    # if there are mismatched hashes, print the number of mismatched hashes and the hashes that are mismatched
    else:
        print(f"{len(mismatched_hashes)} Changes found")
        for file, old_hash, new_hash in mismatched_hashes:
            if new_hash is None:
                if old_hash:
                    print(f"File: {file.ljust(30)} Reference Hash: {old_hash.ljust(32)} ->" + "File is Missing".rjust(31))
                   
            else:
                if old_hash:   
                    print(f"File: {file.ljust(30)} Reference Hash: {old_hash.ljust(32)} -> Current Hash: {new_hash.ljust(32)}")
                else:
                    print(f"File: {file.ljust(30)} Reference Hash: {str(old_hash).ljust(32)} -> Current Hash: {new_hash.ljust(32)}")

        # create the file name for the Hash_Browns file
        hash_browns_filename = "Hash_Browns_" + now.strftime("%Y%m%d-%H%M%S") + ".txt"
        hash_browns_filepath = os.path.join(breakfast_potatoes_dir, hash_browns_filename)

        # write the mismatched hashes to the Hash_Browns file
        with open(hash_browns_filepath, 'w') as f:
            f.write(f"{len(mismatched_hashes)} Changes found\n")
            for file, old_hash, new_hash in mismatched_hashes:
                f.write(f"{file}: {old_hash} -> {new_hash}\n")


        # download zip file containing known malicious hashes
        zip_url = "https://github.com/Len-Stevens/MD5-Malware-Hashes/raw/main/MD5%20Hahses.zip"
        zip_response = requests.get(zip_url)
        zip_contents = zip_response.content
        
        # save the zip file to the Breakfast_Potatoes directory
        zip_filename = "MD5_Hashes.zip"
        zip_filepath = os.path.join(breakfast_potatoes_dir, "MD5_Hashes.zip")
        with open(zip_filepath, 'wb') as f:
            f.write(zip_contents)
            f.close()
        
        
	
        # extract the text file from the zip file
        with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
            text_filename = zip_ref.namelist()[0]
            zip_ref.extractall(breakfast_potatoes_dir)


        # create a set of known malicious hashes from the text file
        malicious_hashes = set()
        with open(os.path.join(breakfast_potatoes_dir, text_filename), 'r') as f:
            for line in f:
                malicious_hashes.add(line.strip())

# check if any of the mismatched hashes are in the malicious hashes set
for file, old_hash, new_hash in mismatched_hashes:
    if new_hash in malicious_hashes:
        print(f"ALERT: {file.ljust(30)} has a hash that matches a known malicious file: {new_hash}")

        # delete any files whose hashes match known malicious hashes
        deleted_files = []
        for file, new_hash in hashes.items():
            if new_hash in malicious_hashes:
                os.remove(file)
                deleted_files.append(file)

        # print an alert for each deleted file
        if deleted_files:
            print(f"ALERT: {len(deleted_files)} file(s) have been deleted due to the hash(es) matching the hash(es) of known malicious files:")
            for file in deleted_files:
                print(f"  {file.ljust(30)}")
