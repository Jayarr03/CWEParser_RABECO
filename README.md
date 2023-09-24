# CWEParser
The CWEParser makes it easy to convert the most recent version of the official cwe list
to a .json file. 

There are two separate approaches. The first uses text parsing and can be used by executing textparser.py.
The second and cleaner approach uses ElementTree to parse the .xml file and grab relevant parts of the data. By
executing etparser.py, you'll use this approach.

No matter which approach you use, there will be no unnecessary files left
because they're cleaned up in the process.