'''
File: plot.py
Authors: Logan Dihel
Date: 5/25/2018
Last Modified: 5/25/2018
Description: This module is a high-level interface
for manipulating and graphing netcdf4 files.
'''

import os
import re
import sys
import copy
import numpy as np
from netCDF4 import Dataset
from netCDF4 import MFDataset
import matplotlib.pyplot as plt
from datetime import datetime, timedelta


class Plotter:
    def __init__(self, path, regexes=[r'.*?']):
        '''Load every file in a path that matches the regex.
        Then jumble all the data up together.
        '''
        files = [os.path.join(path, x) \
                for x in os.listdir(path) \
                if any(re.match(pattern, x) for pattern in regexes)]

        self.time = np.array([])
        # normalize time first
        fhs = [Dataset(x) for x in files]
        fhs.sort(key=lambda fh: fh.variables['time'].getncattr('units'))
        base_time = datetime.strptime(
            ' '.join(fhs[0].variables['time'].getncattr('units').split(' ')[2:4]),
            '%Y-%m-%d %H:%M:%S')
        epoch = datetime.utcfromtimestamp(0)
        for fh in fhs:
            abs_time = datetime.strptime(
                ' '.join(fh.variables['time'].getncattr('units').split(' ')[2:4]),
                '%Y-%m-%d %H:%M:%S'
            )
            dt = abs_time - base_time
            time_data = fh.variables['time'][:]
            correction = np.full_like(time_data, dt.total_seconds() + \
                (base_time - epoch).total_seconds()) # offset by X seconds
            adjep_data = time_data + correction
            self.time = np.append(
                self.time, np.array([datetime.utcfromtimestamp(x) for x in adjep_data])
            )

        # get the rest of the data
        self.mf = MFDataset(files)
        for name in self.mf.variables.keys():
            self.mf.variables[name][:] = \
                np.ma.masked_greater(self.mf.variables['wind_v'][:,0], 9e+36)

    def plot(self):
        pass

    