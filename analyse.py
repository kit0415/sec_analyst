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

def generateBruteForceLogs(df):	
	entriesindex=0
	bigList = []
	loginpage=''
	matchforIPFound = False
	isAnomalyFound=False
	for index, entry in df.iterrows():
		d = entry[2]
		d= d.replace('[','')
		d=d.replace(']','')
		timezone = d.split("+")[1]
		#print timezone
		d = d.split("+")[0]
		entry[2] = d
		#if loginpage in entry[3] and "POST" in entry[3]:
		if "POST" in entry[3]:
			if isAnomalyFound==False:
				#print "initial access to login page found. checking to see if it is a brute force..."
				#print "IP:"+entry[0]
				isAnomalyFound = True
				bigList.append(pd.DataFrame(columns = ['1-IP','2-Username','3-Date','4-Request Method','5-Response Code', '6-Bytes Out', '7-Referer','8-User Agent']))
				bigList[entriesindex].loc[len(bigList[entriesindex])] = entry
				entriesindex+=1
			elif isAnomalyFound==True:
				for index in range (len(bigList)):
					#print "#####CHECKING MATCH"
					#print bigList[index].loc[len(bigList[index])-1,'1-IP']
					#print entry[0]
					#print "#####CHECKING MATCH"
					if bigList[index].loc[len(bigList[index])-1,'1-IP'] == entry[0]: #If IP Matches

						#print "IP Match found! Checking if it is within 3 seconds....."
						currentLogTime = datetime.datetime.strptime(entry[2], "%d/%b/%Y:%H:%M:%S")
						previousLogTime = datetime.datetime.strptime(bigList[index].loc[len(bigList[index])-1,'3-Date'], "%d/%b/%Y:%H:%M:%S")
						if (currentLogTime-previousLogTime).total_seconds()<4:
							#print "Next IP match occurred in "+str((currentLogTime-previousLogTime).total_seconds())+" seconds! Continuing to seek anomaly"
							bigList[index].loc[len(bigList[index])] = entry
							requestarray = entry[3].split()
							loginpage= requestarray[1]
							matchforIPFound = True
				
				if matchforIPFound == False:
							#print "No IP matches for previous entries found, or is not within the same brute force session. Creating new entry:"
							isAnomalyFound = True
							bigList.append(pd.DataFrame(columns = ['1-IP','2-Username','3-Date','4-Request Method','5-Response Code', '6-Bytes Out', '7-Referer','8-User Agent']))
							bigList[entriesindex].loc[len(bigList[entriesindex])] = entry
							entriesindex+=1		
				matchforIPFound= False
	
	bigList2 = []
	for index in range (len(bigList)):
		if len(bigList[index]) > 4:	
			bigList2.append(bigList[index])
	if len(bigList2)>1:
		resultDf = pd.concat(bigList2)
	elif len(bigList2)==1: 
		resultDf= bigList2[0]
	else: #if search produce no results, return an empty Df
		resultDf = pd.DataFrame(columns = ['1-IP','2-Username','3-Date','4-Request Method','5-Response Code', '6-Bytes Out', '7-Referer','8-User Agent'])
	new_columns = resultDf.columns.values
	resultDf.to_csv(r'bf_csv.csv')
	attackerIPs= resultDf['1-IP'].unique()
	
	loginDf = pd.DataFrame(columns = ['1-IP','2-Username','3-Date','4-Request Method','5-Response Code', '6-Bytes Out', '7-Referer','8-User Agent'])
	entriesIndex2=0
	homepage=''
	for IP in attackerIPs:
		for index in range(len(df)):
			if IP == df['1-IP'].iloc[index] and "POST" in df['4-Request Method'].iloc[index] and loginpage in df['4-Request Method'].iloc[index]: #If IP match and it is a POST request to a login page
				nextIndex = index+1
				if IP == df['1-IP'].iloc[nextIndex] and "GET" in df['4-Request Method'].iloc[nextIndex] and loginpage not in df['4-Request Method'].iloc[nextIndex]: #If next entry's IP matches attacker IP, and is a GET request to a homepage
					requestarray = df['4-Request Method'].iloc[nextIndex].split()
					homepage= requestarray[1]
					break
					
	for IP in attackerIPs:
		for index, entry in df.iterrows():
			if IP == entry[0] and homepage in entry[3] and "GET" in entry[3]: #match in IP, and a GET request to the homepage indicates if the attacker has successfully login
				loginDf.loc[entriesIndex2] = entry
				entriesIndex2+=1
	loginDf.to_csv(r'bflogin_csv.csv')

	
bf_dataset = generateBruteForceLogs(generateApacheLogDf(sys.argv[1]))
