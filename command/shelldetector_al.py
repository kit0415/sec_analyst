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
	mycols = ["IP","Identity","Username","Date","Date 2","Request Method","Response Code","Bytes Out","Referer","User Agent"]
	av = pd.read_csv(filepath,sep=" ", names=mycols)
	df = pd.DataFrame({
    "1-IP":av["IP"],
    "2-Username":av["Username"],
    "3-Date":av["Date"]+av["Date 2"],
    "4-Request Method":av["Request Method"],
    "5-Response Code":av["Response Code"],
    "6-Bytes Out":av["Bytes Out"],
    "7-Referer":av["Referer"],
    "8-User Agent":av["User Agent"]
})
	df = df.fillna("-")
	return df

def generateWebshellUploadDf(df, webshellpath):
	webshellpath = 'webshell.php' #remove later, static for now
	
	shellactivitydf = pd.DataFrame(columns = ['1-IP','2-Username','3-Date','4-Request Method','5-Response Code', '6-Bytes Out', '7-Referer','8-User Agent'])
	entryindex =0
	for index,entry in df.iterrows():
		if webshellpath in entry[3]:
			shellactivitydf.loc[entryindex] = entry
			entryindex+=1
			
	shellactivitydf.to_csv(r'bfshelldetect_csv.csv')
	
generateWebshellUploadDf(generateApacheLogDf(sys.argv[1]), sys.argv[2])
	