import pandas as pd
from datetime import datetime,  timedelta
import re

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return "-"

def AnalysisAL(auditlogfile, ignoreroot):

    #use ausearch to clean and format audit.log
    #start_date = datetime.strptime(start_date, '%m/%d/%Y %H:%M:%S')
    #end_date = start_date + timedelta(hours=timespan)
    #e.g ausearch -if audit.log --start 09/24/2019 11:15:24 --end 10/24/2019 11:15:24 -i > ausearch.log
    #without date ausearch -if audit.log -i > ausearch.log
    #ausearch -if audit.log --start start_date --end end_date -i > ausearch.log

    ausearchlog = auditlogfile
    df = pd.DataFrame()

    df = pd.DataFrame(columns=("timestamp", "command", "path", "uid", "exe", "nametype", "workingdirectory"))

    with open(ausearchlog) as records:
        for line in records:
            if '---' in line:
                continue
            else:
                uid = find_between(line, "uid=", " ")
                if (ignoreroot == True and uid == "root"):
                    continue

                timestamp = find_between(line, "msg=audit(", ")")
                name = find_between(line, "name=", " ")
                exe = find_between(line, "exe=", " ")
                nametype = find_between(line, "nametype=", " ")
                workingdir = find_between(line, "cwd=", " ")


                proctitle = "-"
                try:
                    proctitle = line[line.index("proctitle=") + len("proctitle="):]
                except:
                    proctitle = "-"

                #Filter nonvaluable records
                if (proctitle == "/usr/bin/nautilus" or exe == "/usr/bin/nautilus" or  "/usr/bin/nautilus" in proctitle):
                    continue

                df = df.append({'timestamp' : timestamp , "command" : proctitle, 'path' : name, 'uid' : uid, 'exe' : exe, 'nametype' : nametype, 'workingdirectory' : workingdir} , ignore_index=True)



    return df

def printFullAL(df):
    print(df.to_string())

def printSuspiciousAuditActivity(df):
    image_ext_list = ['jpg', 'png', 'jpeg', 'TIF', 'gif']
    first_suspicious_date = "null"

    #find suspicious upload file -> not image
    print "Non-Image Suspicious files Created:"
    for index, row in df.iterrows():
        #Check for upload files
        if ("/var/www/html/sa/3204/uploads/" in row['path']):
            filename = row['path'].replace("/var/www/html/sa/3204/uploads/", "")
            filename = filename.replace(" ", "")

            extension = filename[filename.index(".") + len("."):].lower()
            if (extension in image_ext_list):
                continue
            else:
                if (first_suspicious_date == "null"):
                    first_suspicious_date = row['timestamp']
                print filename
    return first_suspicious_date

#print command executed
def printCommandExecutedBySuspTime(df, first_susp_timestamp):
    search = False
    for index, row in df.iterrows():
        if row['timestamp'] == first_susp_timestamp:
           search = True

        if (search == True):
            if row['command'] != '-' and "/usr/sbin/apache2 -k start" not in row['command']:
                print row['timestamp'] + '\t' + row['command']


def printModifiedFiles(df, first_susp_timestamp):
    print "\nPossible Files Modified:"
    linux_mod_commands = [' nano ', ' gedit ', ' vim ', ' vi ', ' echo ', ' emacs ']
    search = False

    for index, row in df.iterrows():
        if row['timestamp'] == first_susp_timestamp:
            search = True

        if (search == True):
            if row['command'] != '-' and "/usr/sbin/apache2 -k start" not in row['command']:
                for mod_com in linux_mod_commands:
                    if(mod_com in row['command']):
                        print row['timestamp']+ " " + row['command']

def printDeletedFiles(df, first_susp_timestamp):
    print "\nPossible Files Deleted:"
    linux_delete_commands = [' rm ', ' unlink ', ' rmdir ']
    search = False

    for index, row in df.iterrows():
        if row['timestamp'] == first_susp_timestamp:
            search = True

        if (search == True):
            if row['command'] != '-' and "/usr/sbin/apache2 -k start" not in row['command']:
                for mod_com in linux_delete_commands:
                    if(mod_com in row['command']):
                        print row['timestamp'] + " " + row['command']



auditlog_df = AnalysisAL("../data/ausearch.log", True)
first_susp_timestamp = printSuspiciousAuditActivity(auditlog_df)

print "First suspicious timestamp: " + first_susp_timestamp + "\n"

print "Suspicious command from " + first_susp_timestamp + ":\n"
printCommandExecutedBySuspTime(auditlog_df, first_susp_timestamp)

printModifiedFiles(auditlog_df, first_susp_timestamp)

printDeletedFiles(auditlog_df, first_susp_timestamp)