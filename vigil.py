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
train = pd.read_csv('datasets/Train_data.csv')
test = pd.read_csv('datasets/Test_data.csv')
train.drop(['num_outbound_cmds'], axis=1, inplace=True) # Redundant Data
test.drop(['num_outbound_cmds'], axis=1, inplace=True) # Redundant Data
train.drop_duplicates(subset=train.columns[1:],inplace=True) # Redundant Data
print(kl.missingval_plot(train,figsize=(6,5))) # Double-Check Missing Values


# Display Data
print(train['class'].value_counts())
print(train.shape)


