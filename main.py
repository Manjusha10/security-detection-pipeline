
import json

from ipwhois import IPWhois


import pandas as pd
from utils.Mparser import parse_logs
from Detections.DeviceCodePhishing import rule_DeviceCodePhishing


df=parse_logs("Data/data.json")
print("Parsed successfully")



Alert_DeviceCodePhishing=rule_DeviceCodePhishing(df)

print(Alert_DeviceCodePhishing)
Alerts=[Alert_DeviceCodePhishing]

print(f"Generating Alerts")


with open("alerts.json",'w') as f:
    json.dump(Alerts,f,indent=4)

