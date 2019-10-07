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

def GetAuditLogDataFrame(auditlogfile):

    ausearchlog = auditlogfile
    df = pd.DataFrame()
    df = pd.DataFrame(columns=("timestamp", "command", "path", "uid", "exe", "nametype", "workingdirectory"))

    with open(ausearchlog) as records:
        for line in records:
            if '---' in line:
                continue
            else:
                uid = find_between(line, "uid=", " ")
                if (uid == "root"): #ignore commands executed by root
                    continue

                timestamp = find_between(line, "msg=audit(", ")")
                name = find_between(line, "name=", " ")
                exe = find_between(line, "exe=", " ")
                nametype = find_between(line, "nametype=", " ")
                workingdir = find_between(line, "cwd=", " ")
                inode = find_between(line, "inode=", " ")


                proctitle = "-"
                try:
                    proctitle = line[line.index("proctitle=") + len("proctitle="):]
                except:
                    proctitle = "-"

                #Filter nonvaluable records
                if (proctitle == "/usr/bin/nautilus" or exe == "/usr/bin/nautilus" or  "/usr/bin/nautilus" in proctitle):
                    continue

                df = df.append({'timestamp' : timestamp , "command" : proctitle, 'path' : name, 'uid' : uid, 'exe' : exe, 'inode': inode, 'nametype' : nametype, 'workingdirectory' : workingdir} , ignore_index=True)



    return df

def printFullAL(df):
    print(df.to_string())

def GetNonImageAcitivtity(df):
    image_ext_list = ['jpg', 'png', 'jpeg', 'TIF', 'gif']
    first_suspicious_date = "null"
    file_list = []

    #find suspicious upload file -> not image
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
                file_list.append(filename)

    dfObj = pd.DataFrame(columns=['Suspicious Files'])
    file_list = list(dict.fromkeys(file_list))
    for filename in file_list:
        dfObj = dfObj.append({'Suspicious Files': filename}, ignore_index=True)

    return dfObj

def printSuspiciousFileList(df):
    image_ext_list = ['jpg', 'png', 'jpeg', 'TIF', 'gif']
    first_suspicious_date = "null"
    file_list = []
    file_list = []
    timestamp_list = []

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
                file_list.append(filename)
                timestamp_list.append(row['timestamp'])
    file_list = list(dict.fromkeys(file_list))

    return_list = []
    x = range(len(file_list))
    for n in x:
        print n
        return_list.append([timestamp_list[n], file_list[n]])
    return return_list

#print command executed
def GetCommandsExecuted(df, first_susp_timestamp):
    search = False
    dfObj = pd.DataFrame(columns=['Timestamp', 'Commands'])
    first_susp_timestamp_dt = datetime.strptime(first_susp_timestamp, "%m/%d/%Y %H:%M:%S")

    for index, row in df.iterrows():
        ts = row['timestamp']
        ts = ts.split(".", 1)[0]
        ts_dt = datetime.strptime(ts, "%m/%d/%Y %H:%M:%S")
        if ts_dt >= first_susp_timestamp_dt:
           search = True

        if (search == True):
            if row['command'] != '-' and "/usr/sbin/apache2 -k start" not in row['command']:
                #print row['timestamp'] + '\t' + row['command']
                dfObj = dfObj.append({'Timestamp': row['timestamp'], 'Commands': row['command']}, ignore_index=True)

    return dfObj


def GetModifiedFiles(df, first_susp_timestamp):
    linux_mod_commands = [' nano ', ' gedit ', ' vim ', ' vi ', ' echo ', ' emacs ']
    search = False
    dfObj = pd.DataFrame(columns=['Timestamp', 'Commands'])
    first_susp_timestamp_dt = datetime.strptime(first_susp_timestamp, "%m/%d/%Y %H:%M:%S")

    for index, row in df.iterrows():
        ts = row['timestamp']
        ts = ts.split(".", 1)[0]
        ts_dt = datetime.strptime(ts, "%m/%d/%Y %H:%M:%S")
        if ts_dt >= first_susp_timestamp_dt:
            search = True

        if (search == True):
            if row['command'] != '-' and "/usr/sbin/apache2 -k start" not in row['command']:
                for mod_com in linux_mod_commands:
                    if(mod_com in row['command']):
                        #print row['timestamp']+ " " + row['command']
                        dfObj = dfObj.append({'Timestamp': row['timestamp'], 'Commands': row['command']},ignore_index=True)
    return dfObj

def GetCreatedFiles(df, first_susp_timestamp):
    linux_mod_commands = [' touch ', ' cp ', ' cat ', ' nano ', ' gedit ', ' vim ', ' vi ', ' echo ', ' emacs ']
    search = False
    dfObj = pd.DataFrame(columns=['Timestamp', 'Commands'])
    first_susp_timestamp_dt = datetime.strptime(first_susp_timestamp, "%m/%d/%Y %H:%M:%S")

    for index, row in df.iterrows():
        ts = row['timestamp']
        ts = ts.split(".", 1)[0]
        ts_dt = datetime.strptime(ts, "%m/%d/%Y %H:%M:%S")
        if ts_dt >= first_susp_timestamp_dt:
            search = True

        if (search == True):
            if row['command'] != '-' and "/usr/sbin/apache2 -k start" not in row['command']:
                for mod_com in linux_mod_commands:
                    if(mod_com in row['command']):
                        #print row['timestamp']+ " " + row['command']
                        dfObj = dfObj.append({'Timestamp': row['timestamp'], 'Commands': row['command']},ignore_index=True)
    return dfObj

def GetDeletedFiles(df, first_susp_timestamp):
    linux_delete_commands = [' rm ', ' unlink ', ' rmdir ']
    search = False
    dfObj = pd.DataFrame(columns=['Timestamp', 'Commands'])
    first_susp_timestamp_dt = datetime.strptime(first_susp_timestamp, "%m/%d/%Y %H:%M:%S")

    for index, row in df.iterrows():
        ts = row['timestamp']
        ts = ts.split(".", 1)[0]
        ts_dt = datetime.strptime(ts, "%m/%d/%Y %H:%M:%S")
        if ts_dt >= first_susp_timestamp_dt:
            search = True

        if (search == True):
            if row['command'] != '-' and "/usr/sbin/apache2 -k start" not in row['command']:
                for mod_com in linux_delete_commands:
                    if(mod_com in row['command']):
                        #print row['timestamp'] + " " + row['command']
                        dfObj = dfObj.append({'Timestamp': row['timestamp'], 'Commands': row['command']},ignore_index=True)
    return dfObj

def getFirstBruteForceTimeFromAccessLog():
    df = pd.read_csv("abc.csv", sep=",")
    df.columns = ["Index", "IP", "Username", "Date", "Request Method", "Response Code", "Bytes Out", "Referer",
                  "User Agent"]
    for index, row in df.iterrows():
        return row['Date']


def printAuditLogFindings():
    #Correlate from brute force attack timing
    first_bf_timestamp = getFirstBruteForceTimeFromAccessLog()
    first_bf_timestamp= first_bf_timestamp.replace('[','')
    first_bf_timestamp = first_bf_timestamp.split("+")[0]
    first_bf_timestamp = re.sub(":"," ",first_bf_timestamp,count=1)
    first_bf_timestamp_dt = datetime.strptime(first_bf_timestamp, '%d/%b/%Y %H:%M:%S')
    first_bf_timestamp_dt = first_bf_timestamp_dt.strftime("%m/%d/%Y %H:%M:%S")

    #Ausearch command on Audit Log
    #use ausearch to clean and format audit.log
    #start_date = datetime.strptime(start_date, '%m/%d/%Y %H:%M:%S')
    #end_date = start_date + timedelta(hours=timespan)
    #e.g ausearch -if audit.log --start 09/24/2019 11:15:24 --end 10/24/2019 11:15:24 -i > ausearch.log
    #without date ausearch -if audit.log -i > ausearch.log
    #ausearch -if audit.log --start start_date --end end_date -i > ausearch.log

    #Full audit log dataframe
    df = GetAuditLogDataFrame("../data/ausearch.log")
    #Output Dataframe for each findings
    GetNonImageAcitivtity_df = GetNonImageAcitivtity(df)
    GetCommandsExecuted_df = GetCommandsExecuted(df, first_bf_timestamp_dt)
    GetModifiedFiles_df = GetModifiedFiles(df, first_bf_timestamp_dt)
    GetCreatedFiles_df = GetCreatedFiles(df, first_bf_timestamp_dt)
    GetDeletedFiles_df = GetDeletedFiles(df, first_bf_timestamp_dt)

    #print to csv
    GetNonImageAcitivtity_df.to_csv('GetNonImageAcitivtity_df.csv')
    GetCommandsExecuted_df.to_csv('GetCommandsExecuted.csv')
    GetModifiedFiles_df.to_csv('GetModifiedFiles.csv')
    GetCreatedFiles_df.to_csv('GetCreatedFiles.csv')
    GetDeletedFiles_df.to_csv('GetDeletedFiles.csv')

#main
printAuditLogFindings()