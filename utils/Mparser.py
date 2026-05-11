import pandas as pd
import json

#Loading logs from file
def parse_logs(file_path):
    with open(file_path,"r") as f:
        data =json.load(f)
    df=pd.json_normalize(data)
    # Handle Timestamp
    df['time'] = pd.to_datetime(df['time'],unit='s')
    return df