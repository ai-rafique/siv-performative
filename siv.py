#!/usr/bin/env python3

# for argument handling
import argparse

# for system operations
import os
import sys


# for information extraction and conversion
import stat
from pwd import getpwuid
from grp import getgrgid

# for hashing, time recording and file making
import hashlib
import time
import json


class SIV:


    def required_info(self,path):
        """
        FYI :  
        getpwuid(os.stat(file_path).st_uid).pw_name
        the st_uid of a file is the user id that exists in /etc/passwd
        It is a number like , say 1000. the getpwuid returns a struct from /etc/passwd corressponding to uid.
        We just need the name or pw_name attribute. Can't believe easier alterantives to my original plan existed lol
        (Danke schon stack overflow)
        same for group.
        """
        st = os.stat(path)
        size = os.path.getsize(path)
        owner = getpwuid(os.stat(path).st_uid).pw_name
        group = getgrgid(os.stat(path).st_gid).gr_name
        permission = stat.filemode(st.st_mode)
        last_modified = time.ctime(os.path.getmtime(path))
        return size,owner,group,permission,last_modified

    def does_directory_exist(self,monitored_directory):
        if os.path.exists(monitored_directory):
            print("Directory Exists\n")
            return True
        else:
            print("Directory does not exist. Specify an existing directory or create it.\n")
            return False
    
    def documents_maker(self,monitored_directory,verification_db,report_file,mode):
        if os.getcwd() == monitored_directory:
            print('Please Stay outside the monitoring directory')
            sys.exit()
        elif monitored_directory == verification_db.split('/')[0]:
            print('Please Make use of a VerificationDB outside of monitoring directory')
            sys.exit()
        elif monitored_directory == report_file.split('/')[0]:
            print('Please Make Report file outside of monitoring directory')
            sys.exit()
        # all good so make those files now (if init overwrite verifydb else make and for verify do same for report)
        else:
            if mode == "i":
                if os.path.exists(verification_db):
                    print("Overwrite Existing Verification DB\n")
                    os.open(verification_db, os.O_CREAT, mode=0o0777)
                else:
                    os.open(verification_db, os.O_CREAT, mode=0o0777)
                    print("Created Verification DB\n")

                if os.path.exists(report_file):
                    print("Report file exist\n")
                else:
                    print("Creating Report file\n")
                    os.open(report_file, os.O_CREAT, mode=0o0777)
                    
            if mode == "v":
                if os.path.exists(verification_db):
                    print("Using information from Existing Verification DB\n")
                else:
                    # maybe a size check should be used? Nah, not for this assignment.
                    print("Please create a verificationDB first\n")
                    sys.exit()

                if os.path.exists(report_file):
                    print("Report file exist, overwriting contents\n")
                    os.open(report_file, os.O_CREAT, mode=0o0777)
                else:
                    print("Creating Report file\n")
                    os.open(report_file, os.O_CREAT, mode=0o0777)

    def initialization_function(self,args):
        file_counter = 0
        directory_counter = 0
        json_file = ""
        file_info = {}
        message_digest = ""
        """
        find monitored directory and if not create it before runnig the code
        """

        if not self.does_directory_exist(args.monitored_directory):
            sys.exit()


        """
        check if verification and report file exist/need to be made.
        also ensure they are not inside monitoring directory
        This can act like a procedural code flag.

        The function checks location of execution and position of verification and report file.
        If and when all good, it makes them, otherwise exit.

        (maybe a cleaner would be nice)
        """
        self.documents_maker(args.monitored_directory,args.verification_db,args.report_file,"i")
 
        # check if proper hash functions used
        if args.hash not in ["sha1", "md5"]:
            print("allowed values for hashing are sha1 and md5 (case sensitive)\n")
            sys.exit()

        """
            At this point, it should be the case that
            1. verificationDb exists
            2. report file exists
            3. both are outside monitoring directory
            4. appropriate hash functions are in place

            With all conditions set, we just need to collect relevant info and paste them to the report/verificationDB.

            The following for loop (courtesy satckoverflow ) allows us to recursively traverse directories.
            Next is a matter of information retrieval and posting it (YAAY)

            The information extraction task is performed by required_info() function.
            """
        start = time.time()  # recording initialization time start
        for subdir, dirs, files in os.walk(args.monitored_directory):
            for filename in files:
                file_path = subdir + os.sep + filename
                size,owner,group,permission,last_modified = self.required_info(file_path)
                # set digest to specified hash method
                if args.hash in ["sha1"]:
                    hashing_func = hashlib.sha1()
                    with open(file_path, 'rb') as afile:
                        buf = afile.read()
                        hashing_func.update(buf)
                        message_digest = hashing_func.hexdigest()

                if args.hash in ["md5"]:
                    hashing_func = hashlib.md5()
                    with open(file_path, 'rb') as afile:
                        buf = afile.read()
                        hashing_func.update(buf)
                        message_digest = hashing_func.hexdigest()

                file_info[file_path] = {"Full path to file/directory": file_path,
                                        "Size of the file": size,
                                        "Name of user owning the file/directory": owner,
                                        "Name of group owning the file/directory": group,
                                        "Access rights to the file/directory (symbolic)": permission,
                                        "Last modification date": last_modified,
                                        "Computed message digest with": message_digest,
                                        "specified hash function over file contents": args.hash}

                file_counter = file_counter+1
                json_file = json.dumps(file_info, indent=4)

            for dir in dirs:
                directory_path = subdir + os.sep + dir
                size,owner,group,permission,last_modified = self.required_info(directory_path)

                file_info[directory_path] = {"Full path to file/directory": directory_path,
                                            "Size of the file": size,
                                            "Name of user owning the file/directory": owner,
                                            "Name of group owning the file/directory": group,
                                            "Access rights to the file/directory (symbolic)": permission,
                                            "Last modification date": last_modified}

                directory_counter = directory_counter+1
                json_file = json.dumps(file_info, indent=4)

        end = time.time()   # recording initialization time end
        with open(args.verification_db, "w") as the_file:
            the_file.write(json_file)
            print("Verification file generated\n")

        jsonified_report = json.dumps({"Full path of monitored directory": args.monitored_directory,
                                    "Full pathname to verification file": os.path.abspath(args.verification_db),
                                    "Number of directories traversed": directory_counter,
                                    "Number of files traversed": file_counter,
                                    "Time to complete the initialization mode": (end-start)*1000}, indent=4)

        with open(args.report_file, "w") as the_file:
            the_file.write(jsonified_report)
            print("Report file generated\n")
            print("Initialization mode completed\n")


    def verification_function(self,args):
        file_counter = 0
        directory_counter = 0
        changes = 0
        message_digest = ""
        # reusability time XD
        """
        so initital file operations for verification required were that
        1. verificationDB must exist
        2. If it exists, good.
        3. Obviously, we do not have to create the verificationDB in this step.
        4. If report file by that name exists, overwrite, else make new :)
        """
        self.does_directory_exist(args.monitored_directory)

        """
            check if verification and report file exist/need to be made.
            also ensure they are not inside monitoring directory
        """
        self.documents_maker(args.monitored_directory,args.verification_db,args.report_file,"v")

        """
            So this is where making the json like format comes in handy.
            Should add earlier but since verification is a comparison step, 
            having a json structure would be easier to use to compare values as json acts in a
            dictionary like manner, meaning we have keys we can call on that json like body make in the
            initialization step and make a comparison with the value we get on the fly with the code.

            Although its much easier to generate 2 files, 1 before and 1 after and basically run initialize twice,
            (like how its being done right now) the objectives of the assignment are to use the same verification file 
            and multiple report for the step so what is done is to run the init steps and make the 
            key-val pair and load the verification file and check.
            """
        with open(args.verification_db) as verificationdb:
            verification_json = json.load(verificationdb)

        with open(args.report_file, "w") as the_file:
            start = time.time()  # recording verification time start
            for subdir, dirs, files in os.walk(args.monitored_directory):

                for filename in files:
                    
                    
                    file_path = subdir + os.sep + filename
                    size,owner,group,permission,last_modified = self.required_info(file_path)
                    # Now assuming there are changes, we will record first and then check hash differences

                    """
                    The logic is simple. 
                    Since we are comparing values we get now against a previously loaded json structure

                    the key is the path to file, and we already get them from this os.walk loop.
                    Now we check if path and key match,
                    If the path exists, check size,owner,group and other details and record differences if any.
                    If the path is not in the json keys, its likely that the file either does not exist or new added.
                    From this loop, its the latter that holds true since this is a fresh walk into the directory.
                    After the file and directory comparison traversal is done, we can perform an independent comparison
                    on the keys where we can use the os.path.exist function on the key to check if the path exists.
                    If not, its deleted.
                    """
                    if file_path in verification_json.keys():

                        if size != verification_json[file_path]["Size of the file"]:
                            the_file.write(
                                "\nIntegrity Change Detected : The file " + file_path + " size has changed. (OLD :"+str(verification_json[file_path]["Size of the file"])+", NEW:"+str(size)+")\n")
                            changes = changes+1
                        if owner != verification_json[file_path]["Name of user owning the file/directory"]:
                            the_file.write(
                                "\nIntegrity Change Detected : The owner of file " + file_path + " has been changed.(OLD :"+verification_json[file_path]["Name of user owning the file/directory"]+", NEW:"+owner+")\n")
                            changes = changes+1
                        if group != verification_json[file_path]["Name of group owning the file/directory"]:
                            the_file.write(
                                "\nIntegrity Change Detected : The group of file " + file_path + " has been changed.(OLD :"+verification_json[file_path]["Name of group owning the file/directory"]+", NEW:"+group+")\n")
                            changes = changes+1
                        if permission != verification_json[file_path]["Access rights to the file/directory (symbolic)"]:
                            the_file.write(
                                "\nIntegrity Change Detected :" + file_path + " has different accesss rights.(OLD :"+verification_json[file_path]["Access rights to the file/directory (symbolic)"]+", NEW:"+permission+")\n")
                            changes = changes+1
                        if last_modified != verification_json[file_path]["Last modification date"]:
                            the_file.write("\nIntegrity Change Detected :" +
                                        file_path + " has different last modified date.(OLD :"+verification_json[file_path]["Last modification date"]+", NEW:"+last_modified+")\n")
                            changes = changes+1

                        hash_type = verification_json[file_path]["specified hash function over file contents"]

                    # set digest to specified hash method
                        if hash_type in ["sha1"]:
                            hashing_func = hashlib.sha1()
                            with open(file_path, 'rb') as afile:
                                buffer = afile.read()
                                hashing_func.update(buffer)
                                message_digest = hashing_func.hexdigest()
                                if message_digest != verification_json[file_path]["Computed message digest with"]:
                                    the_file.write(
                                        "\nIntegrity Change Detected :" + file_path + " has different message digest.(OLD :"+verification_json[file_path]["Computed message digest with"]+", NEW:"+message_digest+")\n")
                                    changes = changes+1

                        if hash_type in ["md5"]:
                            hashing_func = hashlib.md5()
                            with open(file_path, 'rb') as afile:
                                buffer = afile.read()
                                hashing_func.update(buffer)
                                message_digest = hashing_func.hexdigest()
                                if message_digest != verification_json[file_path]["Computed message digest with"]:
                                    the_file.write(
                                        "\nIntegrity Change Detected :" + file_path + " has different message digest.(OLD :"+verification_json[file_path]["Computed message digest with"]+", NEW: "+message_digest+")\n")
                                    changes = changes+1
                    else:
                        the_file.write("\nIntegrity Change Detected :" +
                                    file_path + " has been added to monitoring directory\n")
                        changes = changes+1
                    file_counter = file_counter+1

                for dir in dirs:
                    
                    directory_path = subdir + os.sep + dir
                    size,owner,group,permission,last_modified = self.required_info(directory_path)

                    if directory_path in verification_json.keys():
                        if size != verification_json[directory_path]["Size of the file"]:
                            the_file.write(
                                "\nIntegrity Change Detected : The directory " + directory_path + " has different size.(OLD :"+str(verification_json[directory_path]["Size of the file"])+", NEW: "+str(size)+")\n")
                            changes = changes+1
                        if owner != verification_json[directory_path]["Name of user owning the file/directory"]:
                            the_file.write(
                                "\nIntegrity Change Detected : The owner of file " + directory_path + " has been changed.(OLD :"+verification_json[directory_path]["Name of user owning the file/directory"]+", NEW: "+owner+")\n")
                            changes = changes+1
                        if group != verification_json[directory_path]["Name of group owning the file/directory"]:
                            the_file.write(
                                "\nIntegrity Change Detected : The group of file " + directory_path + " has been changed.(OLD :"+verification_json[directory_path]["Name of group owning the file/directory"]+", NEW: "+group+")\n")
                            changes = changes+1
                        if permission != verification_json[directory_path]["Access rights to the file/directory (symbolic)"]:
                            the_file.write("\nIntegrity Change Detected :" +
                                        directory_path + " has different accesss rights.(OLD :"+verification_json[directory_path]["Access rights to the file/directory (symbolic)"]+", NEW: "+permission+")\n")
                            changes = changes+1
                        if last_modified != verification_json[directory_path]["Last modification date"]:
                            the_file.write("\nIntegrity Change Detected :" +
                                        directory_path + " has different last modified date.(OLD :"+verification_json[directory_path]["Last modification date"]+", NEW: "+last_modified+")\n")
                            changes = changes+1
                    else:
                        the_file.write(
                            "\nIntegrity Change Detected :" + directory_path + " has been added\n")
                    directory_counter = directory_counter+1

            """
                seperate check for whether directory or file has been removed
                """
            for node in verification_json.keys():
                if os.path.exists(node) == 0:
                    the_file.write("\nIntegrity Change Detected : " + node + " has been deleted\n")
                    changes = changes+1
        end = time.time()  # recording verification time end

        jsonified_report = json.dumps({"Full path of monitored directory": args.monitored_directory,
                                    "Full pathname to verification file": os.path.abspath(args.verification_db),
                                    "Number of directories traversed": directory_counter,
                                    "Number of files traversed": file_counter,
                                    "Time to complete the verification mode": (end-start)*1000,
                                    "Number of changes detected": changes}, indent=4)

        with open(args.report_file, "a") as final_report:
            final_report.write(jsonified_report)
            print("Verification mode completed\n")


"""
Okay so we can only be in initilialization or verification mode
we have multiple ways but luckily the add_mutually_exclusive_group() in argparse helps
Now -D,-V,-R are required in 3 but -H only when -i is used, so appropriate workable 
condition will be set.

So an if condition will be created which willrun only when possible tru conditions are met

Namespace(init=False, verify=True, monitored_directory='jelp', verification_db='verifyME', report_file='reportMe', hash='md5')
easiest is to make single execution points and exit if fasle.

Could be made better though but too mentally drained to thing so far T_T
"""


def main():

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--init", action="store_true",help="Directory initialization mode")
    group.add_argument("-v", "--verify", action="store_true",help="Directory verification mode")
    parser.add_argument("-D", "--monitored_directory",type=str, help="Specifiy directory to monitor")
    parser.add_argument("-V", "--verification_db", type=str,help="Where to keep verification data (outside monitored directory please)")
    parser.add_argument("-R", "--report_file", type=str,help="Where to keep report data (outside monitored directory please)")
    parser.add_argument("-H", "--hash", type=str,help="Use hashing function (sha1 or md5)")
    args = parser.parse_args()

    if args.init and args.monitored_directory and args.verification_db and args.report_file and args.hash:
        print('init time')
        siv = SIV()
        siv.initialization_function(args)

    elif args.verify and args.monitored_directory and args.verification_db and args.report_file and not args.hash:
        print('verify time')
        siv = SIV()
        siv.verification_function(args)
    else:
        print('Invalid argument style. Please use python3 siv.py -h to get USAGE')


if __name__ == "__main__":
    main()
