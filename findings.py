import re
import os
import pandas as pd
from dateutil.parser import parse
from datetime import date
import datetime
import time
import sys
import csv
from dateutil.relativedelta import relativedelta

def generateApacheLogDf(filepath):
	mycols = ["Index","IP","Username","Date","Request Method","Response Code","Bytes Out","Referer","User Agent"]
	av = pd.read_csv(filepath,sep=",", names=mycols)
	df = pd.DataFrame({
	"0-Index":av["Index"],
    "1-IP":av["IP"],
    "2-Username":av["Username"],
    "3-Date":av["Date"],
    "4-Request Method":av["Request Method"],
    "5-Response Code":av["Response Code"],
    "6-Bytes Out":av["Bytes Out"],
    "7-Referer":av["Referer"],
    "8-User Agent":av["User Agent"]
})
	df = df.fillna("-")
	return df

def printDetails(df):
	startTime = datetime.datetime.strptime(str(df['3-Date'].iloc[1]), "%d/%b/%Y:%H:%M:%S")
	endTime =   datetime.datetime.strptime(str(df['3-Date'].iloc[-1]), "%d/%b/%Y:%H:%M:%S")
	print '<p>Start Time of Brute Force: '+str(startTime)+'</p>'
	print 'End Time of Brute Force: '+str(endTime)
	diff = relativedelta(endTime, startTime)
	print "Brute Force duration: %d days %d hours %d minutes %d seconds" % (diff.days, diff.hours, diff.minutes, diff.seconds)
	UserAgentCount = df['8-User Agent'].iloc[1:].value_counts(sort=False)
	userAgentCount2 = []
	userAgentList = []
	for index, item in UserAgentCount.iteritems():
		userAgentCount2.append(int(item))
		userAgentList.append(index)

	print '\nList of User Agents used by attacker:'
	for index in range (len(userAgentList)):
		print userAgentList[index] +": "+str(userAgentCount2[index])+ " occurrences"
		
	IPCount = df['1-IP'].iloc[1:].value_counts(sort=False)
	IPCount2 = []
	IPList = []
	for index, item in IPCount.iteritems():
		IPCount2.append(int(item))
		IPList.append(index)

	print '\nList of IPs conducting the attack:'
	for index in range (len(IPList)):
		print IPList[index] +": "+str(IPCount2[index])+ " occurrences"
	
	requestarray = df['4-Request Method'].iloc[1].split()
	print 'Login page being breached(URL):'+ requestarray[1]
	
	loginDf = generateApacheLogDf('bflogin_csv.csv')
	requestarray= loginDf['4-Request Method'].iloc[1].split()
	print 'Home page URL:'+ requestarray[1]
		
printDetails(generateApacheLogDf(sys.argv[1]))
	