import pandas as pd
import matplotlib.pyplot as plt
import re

def pcapDF():
    fileName = "PcapFileSept24.csv"
    df = pd.read_csv(fileName, header=0)
    df["frame.time"] = pd.to_datetime(df["frame.time"]).dt.strftime("%d-%m-%Y %H:%M:%s")
    df = df.fillna("-")
    return df

def findServer(df):
    df = df[df["http.host"] != '-']
    df = df["http.host"].unique()
    return df

def getUniqueHost(df):
    #fileName = "PcapFileSept24.csv"
    serverIp = findServer(df)
    excludedIP = [serverIp, "192.168.43.1", "172.217.194.190"]
    #df = pd.read_csv(fileName, header=0)
    df = df['ip.src'].unique()
    uniqueIP = [x for x in df if x not in excludedIP]
    return uniqueIP

def getUniqueTime(df):
    df = df['frame.time'].unique()
    uniqueTime = [x for x in df]
    return uniqueTime

def checkHost(ip_add,df):
    # fileName = "PcapFileSept24.csv"
    # df = pd.read_csv(fileName, header=0)
    # df = df.fillna("-")
    serverIp = findServer(df)
    print "Server IP is",serverIp
    df_filtered = df[(df["ip.src"] == ip_add) | (df["ip.src"]==str(serverIp[0]))]
    # print df_filtered
    # print type(df_filtered.groupby("ip.src")['tcp.srcport'].nunique())
    # print df_filtered.groupby("ip.src").count()
    return df_filtered

def getPortScanResult():
    originalDF = pcapDF()
    checkIP = getUniqueHost(originalDF)
    for ip in checkIP:
        print "IP use is "+ip
        df = checkHost(ip,originalDF).reset_index(drop=True)
        df.to_csv("visual.csv")
        tcp_status = df["tcp.flags"]
        portOpenStartList = list()
        portOpenEndList = []
        indexStartList = list()
        indexEndList =list()
        counter = 0
        print "Len is "+str(len(tcp_status))
        for i in range(len(tcp_status)):
            if tcp_status[i] == "0x00000002" and tcp_status[i+1] == "0x00000014":
                counter +=1
                indexStartList.append(i)
                indexEndList.append(i+1)
            elif tcp_status[i] == "0x00000002" and tcp_status[i+1] == "0x00000012":
                result = findFlags(i+1,tcp_status)
                if result[0] is True:
                    portOpenStartList.append(i)
                    portOpenEndList.append(result[1])
                    print "port 80 is open"
        print "Index end at ",counter
        if (counter > 100):
            scanFlag = 1
            doneList = [ip, scanFlag, indexStartList, indexEndList,portOpenStartList,portOpenEndList]
            portList = getPortList(indexStartList, indexEndList,portOpenStartList,portOpenEndList,df)
            print portList
            print "Suspicios account activity: d",counter
        else:
            scanFlag = 0
            print "IP: "+ip+" had no suspicios scanning activity"
            doneList = [ip, scanFlag]

    return doneList
        #print(df.to_string())

def getPortList(indexStartList, indexEndList,portOpenStartList,portOpenEndList,df):
    print "number of port ",len(indexStartList)
    portList = []
    for item in indexStartList:
        portList.append(df["tcp.dstport"][item])
        print df["tcp.dstport"][item]

    for port in portOpenStartList:
        portList.append(df["tcp.dstport"][port])

    portList = list(dict.fromkeys(portList))
    portList = sorted(portList)
    return portList

def findFlags(startIndex,df):
    found = list()
    print "StartIndex is "+str(startIndex)
    for i in range(startIndex,startIndex+5):
        if df[i] == "0x00000010":
            if df[i+1] == "0x00000014":
                found.append(i)
                print "??: " + str(found)
                return [True,i]

    return [False,0]


def getWebPage(df,time):
    suspiciousDf = df[(df["frame.time"] == time) & (df["http.request.method"] == "POST")]
    url = suspiciousDf["http.request.full_uri"].unique()
    countUrl = len(suspiciousDf["http.request.full_uri"])
    return [url,countUrl]

def getBruteForce():
    bfDF = pcapDF()
    checkIP = getUniqueHost(bfDF)
    print "IP List for bf is ",checkIP
    getList = []
    postList = []
    timingList = []
    attackerIp = ""
    for ip in checkIP:
        print "IP is ",ip
        df = checkHost(ip, bfDF)
        requestDF = df[(df["http.request.method"] == "GET") | (df["http.request.method"] == "POST")].reset_index(drop=True)
        requestDF["frame.time"] = pd.to_datetime(requestDF["frame.time"]).dt.strftime("%d-%m-%Y %H:%M")
        timeList = getUniqueTime(requestDF)
        #webPageList = getWebPage(requestDF)
        filterDf =  requestDF.groupby("frame.time")['http.request.method'].value_counts()
        print filterDf
        for time in timeList:
            getCount = 0
            postCount = 0
            for i in range(len(requestDF)):
                if requestDF["frame.time"][i] == time and requestDF["http.request.method"][i] == "GET":
                    getCount +=1
                elif requestDF["frame.time"][i] == time and requestDF["http.request.method"][i] == "POST":
                    postCount +=1
            if postCount > 10:
                webPageList = getWebPage(requestDF,time)
                attackerIp = ip
                print "Suspecting Bruteforce Activity at timing ", time
                print "Suspecting IP address: ",ip
                print "The URL ",webPageList[0], "is access using POST method."
                print "Peak Request Count: ",webPageList[1]
            timingList.append(time)
            getList.append(getCount)
            postList.append(postCount)

        print timingList
        print getList
        print postList
        # requestDF.groupby("frame.time")['http.request.method'].value_counts().plot(kind="line")
        # plt.xticks(rotation=90)
        # plt.show()


def getBruteForcefake():
    fileName = "PcapFileSept24.csv"
    df = pd.read_csv(fileName, header=0)
    df = df.fillna("-")
    ax = plt.gca()
    df["frame.time"] = pd.to_datetime(df["frame.time"]).dt.strftime("%d-%m-%Y %H:%M")
    df_filtered = df[df["ip.src"] == "192.168.43.202"]
    print df_filtered
    print df_filtered.groupby("frame.time")['ip.src'].nunique()
    df_filtered.groupby("frame.time")['ip.src'].nunique().plot(kind='line')
    #df.plot(kind="line",x="ip.src",y="frame.time",ax=ax)
    plt.show()


getBruteForce()