# siv-performative
A system integrity verifier script made for ET2595 course


## Description
This is a system integrity verifier program written in python in an object oriented manner.
The idea is to store information about a system and be able to verify whether any change has been made to said system.
It checks
1. Size changes
2. Perission changed
3. Ownership changes
4. Modification if any

At files and directory level
It utilizes JSON files as a data store for initialization and uses it to compare for verification

## IMPORTANT
The program is supposed to ensure that the verification and initialization files are not inside the target directory.
However, the function that currently ensures that is not so mature and should be handled with care.


## Environment Used
1. Ubuntu 22.04
2. Python 3.10



## How to use Initialization
./siv.py -i -D data -V vDB -R init.txt -H sha1

## How to use Verification
./siv.py -v -D data -V vDB -R verify.txt

## How to use the tester
sudo ./siv tester.py -s ./siv.py -e orig


# Possible imporvement areas
1. improve the file location check