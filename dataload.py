# -*- coding: utf-8 -*-
"""
Created on Thu Jan 26 04:27:57 2023

@author: PRAMILA
"""
import datetime
import json
import numpy as np
import requests
import base64
import pandas as pd
import streamlit as st
from copy import deepcopy
import tensorflow
from sklearn.preprocessing import StandardScaler
st.markdown("<h1 style ='color:#BB1D3F; text_align:center;font-family:times new roman;font-size:20pt;font-weight: bold;'>Network Intrusion Detector</h1>", unsafe_allow_html=True)
def load_mapping():
    df = pd.read_excel("network_categories.xlsx")
    return df


mapping_df = load_mapping()

#print(mapping_df["Protocol_type"])
valid_protocol_types = ["icmp","tcp","udp"]
valid_service = list(np.unique(mapping_df["Service"].values))

valid_flag = ["SF","S0","REJ","RSTR", "SH","RSTO", "S1","RSTOS0", "S3","S2","OTH" ]


Protocol_type = st.selectbox('Select protocol type', [valid_protocol_types[0]] + valid_protocol_types)
Service = st.selectbox('Select service', [""] + valid_service)
Flag = st.selectbox('Select flag', [""] + valid_flag)
Src_bytes=st.number_input('Enter source bytes',min_value=0, max_value=7665876, value=0, step=1)
Logged_in = st.radio("Logged In status",(0,1))
Count=st.number_input('Enter Number of connections',min_value=0, max_value=600, value=0, step=1)
Srv_count=st.number_input('Number of connections to the same service',min_value=0, max_value=600, value=0, step=1)
Serror_rate=st.number_input('Serror_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Srv_serror_rate=st.number_input('Srv_serror_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
#Rerror_rate=st.number_input('Rerror_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Same_srv_rate=st.number_input('Same_srv_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Diff_srv_rate=st.number_input('Diff_srv_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_count=st.number_input('Dst_host_count',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_srv_count=st.number_input('Dst_host_srv_count',min_value=0, max_value=255, value=0, step=1)
Dst_host_same_srv_rate=st.number_input('Dst_host_same_srv_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_diff_srv_rate=st.number_input('Dst_host_diff_srv_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_same_src_port_rate=st.number_input('Dst_host_same_src_port_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_srv_diff_host_rate=st.number_input('Dst_host_srv_diff_host_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_serror_rate=st.number_input('Dst_host_serror_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_srv_serror_rate=st.number_input('Dst_host_srv_serror_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)
Dst_host_rerror_rate=st.number_input('Dst_host_rerror_rate',min_value=0.0, max_value=1.0, value=0.0, step=0.1)

from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()

le.fit(np.array(valid_protocol_types))
#st.write(le.transform(np.array(valid_protocol_types)))
Protocol_type_trans=le.transform([Protocol_type])


le.fit(np.array(valid_service))
#st.write(le.transform(np.array(valid_service)))
Service_trans=le.transform([Service])
#st.write(Service_trans[0])

le.fit(np.array(valid_flag))
#st.write(le.transform(np.array(valid_flag)))
Flag_trans=le.transform([Flag])
#st.write(Flag_trans[0])


Protocol_type=Protocol_type_trans[0]
Service= Service_trans[0]
Flag= Flag_trans[0]
#st.write(type(Flag))


lst=[int(Protocol_type), int(Service) ,int(Flag), Src_bytes, Logged_in, Count,
 Srv_count, Serror_rate ,Srv_serror_rate ,Same_srv_rate,
 Diff_srv_rate, Dst_host_count,Dst_host_srv_count,
 Dst_host_same_srv_rate, Dst_host_diff_srv_rate,
 Dst_host_same_src_port_rate, Dst_host_srv_diff_host_rate,
 Dst_host_serror_rate ,Dst_host_srv_serror_rate, Dst_host_rerror_rate]
#st.write(lst)
arr = np.array(lst).reshape(-1,1)
#st.write(arr)
#Perform feature scaling
scaler=StandardScaler()
df1=scaler.fit_transform(arr)
#st.write(df1)

result=['apache2','back', 'buffer_overflow', 'ftp_write', 'guess_passwd',
 'httptunnel', 'imap', 'ipsweep', 'land', 'loadmodule', 'mailbomb', 'mscan',
 'multihop', 'named', 'neptune', 'nmap', 'normal', 'perl', 'phf', 'pod',
 'portsweep', 'processtable', 'ps', 'rootkit', 'saint', 'satan', 'sendmail',
 'smurf', 'snmpgetattack', 'snmpguess', 'spy', 'sqlattack', 'teardrop',
 'udpstorm', 'warezclient', 'warezmaster', 'worm', 'xlock', 'xsnoop', 'xterm']


model =tensorflow.keras.models.load_model('modelnew.h5')
if(st.button("predict")):
    test_data = df1.reshape(1,-1)
    o=model.predict(test_data, batch_size=1)
    #st.write(o)
    #st.write(len(o[0]))
    #st.write(o.argmax())
    st.success(result[int(o.argmax())])
