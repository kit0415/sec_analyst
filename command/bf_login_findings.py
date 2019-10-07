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
	requestarray= df['4-Request Method'].iloc[1].split()
	print 'Home page URL:'+ requestarray[1]
	
	startTimeString = str(df['3-Date'].iloc[1])
	endTimeString = str(df['3-Date'].iloc[-1])
	startTimeString= startTimeString.replace('[','')
	startTimeString=startTimeString.replace(']','')
	timezone = startTimeString.split("+")[1]
	startTimeString = startTimeString.split("+")[0]

	endTimeString= endTimeString.replace('[','')
	endTimeString=endTimeString.replace(']','')
	timezone = endTimeString.split("+")[1]
	endTimeString = endTimeString.split("+")[0]

	startTime = datetime.datetime.strptime(startTimeString, "%d/%b/%Y:%H:%M:%S")
	endTime =   datetime.datetime.strptime(endTimeString, "%d/%b/%Y:%H:%M:%S")
	print '<p>First time attacker has logged in: '+str(startTime)+'</p>'
	print '<p>Last time attacker has logged in: '+str(endTime)+'</p>'
	
printDetails(generateApacheLogDf(sys.argv[1]))
	