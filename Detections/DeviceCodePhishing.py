import pandas as pd
from ipwhois import IPWhois

#meta_df=pd.DataFrame({'Name':'Device Code Phishing alert','Description':'Detects Device code phishing attack','Severity':'High','Tactic':'Initial Access','Technique':'Spearphishing Link'})

def rule_DeviceCodePhishing(df):
    alerts=[]
    print("Initiating detection")
    df = df[(df['operationName'] == "Sign-in activity") &
            (df['category'] == "SignInLogs") &
            (df['resultSignature'] == "SUCCESS") &
            (df['properties.authenticationProtocol'] == "deviceCode") &
            (df['properties.appId'] == "29d9ed98-a469-4536-ade2-f981bc1d605e") &
            (df['properties.deviceDetail.trustType'] == "Azure AD Joined")]


    df = df[(pd.Timestamp.now() - df['time']) <= pd.Timedelta(hours=1)]

    for _,row in df.iterrows():
        alert={
            "alert_name": "Device Code Phishing",
            "alert_description": "A Device Code Phishing attack has occurred.",
            "Severity": "High",
            "Tactics":"Initial Access",
            "Technique":"Spearphishing Link",
            "User":row["identity"],
            "IP":row["callerIpAddress"],
            "timestamp":str(row["time"])
        }
        alerts.append(alert)
    return alerts
#def Trigger_Alert:
#Name: Device Code Phishing alert
#Desc:
#severity:
#Tactic:Initial Access
#Technique:Spearphishing Link
#Search window: 1h
#frequency:1h
#Alert_df=pd.concat(['df','meta_df'],axis=0)