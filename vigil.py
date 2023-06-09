# Import Libraries

import matplotlib
import matplotlib.pyplot as plt
import numpy as np 
import pandas as pd
import seaborn as sb
import klib as kl
import sklearn
import imblearn

# Settings
pd.set_option('display.max_columns', None)
np.set_printoptions(precision=3)
sb.set(style='darkgrid')
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['xtick.labelsize'] = 12
plt.rcParams['ytick.labelsize'] = 12

# Loading Datasets
data1 = pd.read_csv('datasets/Monday-WorkingHours.pcap_ISCX.csv')
data2 = pd.read_csv('datasets/Tuesday-WorkingHours.pcap_ISCX.csv')
data3 = pd.read_csv('datasets/Wednesday-WorkingHours.pcap_ISCX.csv')
data4 = pd.read_csv('datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
data5 = pd.read_csv('datasets/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv')
data6 = pd.read_csv('datasets/Friday-WorkingHours-Morning.pcap_ISCX.csv')
data7 = pd.read_csv('datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
data8 = pd.read_csv('datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')



