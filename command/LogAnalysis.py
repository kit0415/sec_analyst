import pandas as pd
import os
from scapy.all import *

def AnalysisAusearchLog(logfile):
    with open(logfile) as infile, open(logfile + ".clean", 'w') as outfile:
        for line in infile:
            if (line[0].isdigit()):
                outfile.write(line)
            else:
                continue

    avRep = logfile + ".clean"

    df = pd.read_csv(avRep, sep=" ", header=None)
    df.columns = ["No", "Date", "Time", "Accessed", "Syscall", "Success", "Command", "User", "UID"]

    #print(av.to_string())
    # for index, row in df.iterrows():
    #    print(row['No'], row['Date'])

def AnaylsisAccessLog(logfile):
    df = pd.read_csv(logfile,
                     sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
                     engine='python',
                     usecols=[0, 3, 4, 5, 6, 7, 8],
                     names=['ip', 'time', 'request', 'status', 'size', 'referer', 'user_agent'],
                     na_values='-',
                     header=None
                     )

def AnaylsisBashHistory(logfile):
    avRep = logfile
    df = pd.read_csv(avRep, sep=" ", header=None)
    df.columns = ["BashCommand"]


def AnaylsisPcapFile(pcapfile):
    #os.system(" tshark -r "+ pcapfile +" -t ad > pcap.txt")

    avRep = "data/pcap.csv"
    df = pd.read_csv(avRep)
    df.columns = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    print(df.to_string())




#AnalysisAusearchLog("data/ausearch.txt")
AnaylsisPcapFile("")