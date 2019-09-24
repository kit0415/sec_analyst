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
    wireSharkcmd = "tshark -2 -r "+pcapfile+" -T fields -E header=y -E separator=, -E occurrence=a -E quote=d -e frame.time -e ip.proto -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e tcp.stream -e tcp.seq -e tcp.flags -e tcp.srcport -e tcp.dstport -e http.request.method -e http.host -e http.request.full_uri -e http.request.version -e http.user_agent -e http.request.uri.query.parameter -e http.request.uri.query -e http.server -e http.response.code -e http.response.phrase 'ip.proto==6'> out1.csv "
    os.system(wireSharkcmd)

    avRep = "data/pcap.csv"
    df = pd.read_csv(avRep)
    df.columns = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    print(df.to_string())




#AnalysisAusearchLog("data/ausearch.txt")
AnaylsisPcapFile("")
