import re
import os
import pandas as pd

mycols = ["IP","Identity","Username","Date","Date 2","Request Method","Response Code","Bytes Out","Referer","User Agent"]
av = pd.read_csv("access.txt",sep=" ", names=mycols)
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

print df
