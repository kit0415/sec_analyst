import pandas as pd
import os
from scapy.all import *
import sys

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


def AnaylsisPcapFile(pcapfile,case,option):
    fileName = "PcapFileSept24new.csv"
    if option is "TCP":
        filterPacket = 'ip.proto==6'
        headerOption = "-e tcp.srcport -e tcp.dstport"
    elif option is "UDP":
        filterPacket = 'ip.proto==17'
        headerOption = "-e udp.srcport -e udp.dstport"
    elif option is "All":
        filterPacket = ""
        headerOption = "-e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport"
    wireSharkcmd = "tshark -2 -r "+pcapfile+" -T fields -E header=y -E separator=, -E occurrence=a -E quote=d -e frame.time -e ip.proto -e ip.src -e ip.dst "+headerOption+" -e tcp.stream -e tcp.seq -e tcp.flags -e http.request.method -e http.host -e http.request.full_uri -e http.request.version -e http.user_agent -e http.request.uri.query.parameter -e http.request.uri.query -e http.server -e http.response.code -e http.response.phrase -e http.content_type "+filterPacket+" > "+fileName
    os.system(wireSharkcmd)

    avRep = "data/pcap.csv"
    df = pd.read_csv(fileName,header=0)
    #df.columns = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    print(df.to_string())



if __name__ == '__main__':
    fileType = sys.argv[1]
    filePath = sys.argv[2]
    if fileType == "pcapng":
        AnaylsisPcapFile(filePath, 1, "TCP")
#AnalysisAusearchLog("data/ausearch.txt")

