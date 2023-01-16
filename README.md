# BreakfastPotatoes
A file integrity tool that automates traversing a given directory and any subdirectories, MD5 hashes every file in the directory and compares those hashes to a the hashes in reference file named Hashed_Potatoes with a date timestamp appended to the file name written to a folder on the desktop titled Breakfast_Potatoes by the tool when it is first run. The user is notified of any changes to the files including the editing of a file, the deletion/removal of a file, and the creation/addition of a file. These changes along with the file name and path are written to a file in the Breakfast_Potatoes folder named Hashed_Browns with a date timestamp appended to the file name. Every edited/new file is compared to a malicious hash list of which the most recent version is downloaded from a GitHub repository at the time of the comparison. If the hash of an edited/new file matches a known malicious hash, the file is automatically deleted and the user is notified.

