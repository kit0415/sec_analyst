import re
import os
import pandas as pd
from dateutil.parser import parse
from datetime import date
import datetime
import time
import sys
import csv

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
	print 'First time attacker has visited the webshell: '+str(startTime)
	print 'Last time attacker has visited the webshell: '+str(endTime)
		
printDetails(generateApacheLogDf(sys.argv[1]))
	