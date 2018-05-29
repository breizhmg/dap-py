'''
File: plot.py
Authors: Logan Dihel
Date: 5/25/2018
Last Modified: 5/29/2018
Description: This module is a high-level interface
for manipulating and graphing netcdf4 files.
'''

import os
import re
import sys
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

    def plot(self, variable_groups, begin=None, end=None, width=18, height=6):
        '''public function for plotting a list of regex tuples/lists/sets
        calls the private _plot method after creating all of the plot groups
        in the correct format. The purpose of this function is two fold:
            1.  Determine the number of plots that will be plotted
            2.  Package all of the plots in a manner that is easy
                to loop over and generate plots quickly
        '''
        plot_groups = []

        for group in variable_groups:

            var_names = {x for pattern in group \
                for x in self.mf.variables.keys() \
                if re.search(pattern, x)}

            shapes = {self.mf.variables[x].shape for x in var_names}
            if len(shapes) != 1:
                print('Could not plot variables {} because of inconsistent shapes: {}'.format(
                    ', '.join( 
                        ['\'{}\''.format(x) for x in var_names]
                    ),
                    ', '.join(
                        ['\'{}\''.format(self.mf.variables[x][:].shape) for x in var_names]
                    )
                ))
                continue

            dimensioned_by = {self.mf.variables[x].dimensions for x in var_names}
            if len(dimensioned_by) != 1:
                print('Could not plot variables {} because of inconsistent dimensions: {}'.format(
                    ', '.join( 
                        ['\'{}\''.format(x) for x in var_names]
                    ),
                    ', '.join(
                        ['\'{}\''.format(self.mf.variables[x].dimensions) for x in var_names]
                    )
                ))
                continue

            shape = list(shapes)[0]
            dimensions = len(shape)
            if dimensions == 0:
                plot_groups.append({
                    'names': var_names,
                    'dimensions': [],
                    'slice': []
                })

            elif dimensions == 1:
                plot_groups.append({
                    'names': var_names,
                    'dimensions': list(dimensioned_by)[0],
                    'slice': [None]
                })

            elif dimensions == 2:
                for column in range(shape[1]):
                    plot_groups.append({
                        'names': var_names,
                        'dimensions': list(dimensioned_by)[0],
                        'slice': [None, column]
                    })

            else:
                print('3 dimensional matrix plots are not yet implemented')
                continue

        if plot_groups:
            self._plot(plot_groups, begin, end, width, height)

    def _plot(self, plot_groups, begin, end, width, height):
        '''actually plots the data
        '''
        num_plots = len(plot_groups)
        fig = plt.figure(figsize=(width, height * num_plots))
        colors = ['b', 'g', 'r', 'c', 'm', 'y', 'k', 'w']

        # slice the time range
        start_index = bin_search(self.time, begin) \
            if begin else 0
        end_index = bin_search(self.time, end) + 1 \
            if end else self.time.size

        for i, group in enumerate(plot_groups):
            
            dimensions = len(group['dimensions'])
            ax = fig.add_subplot(num_plots, 1, i+1)
            var_names = group['names']

            for j, var_name in enumerate(var_names):
                # plot each variable on the same graph
                if dimensions == 0:
                    y = np.ma.masked_greater(
                        self.mf.variables[var_name][start_index:end_index],
                        9e+36
                    )

                    if y.count() > 0:
                        ax.plot(y,marker='o', color=colors[j % len(colors)])

                elif dimensions == 1:
                    y = np.ma.masked_greater(
                        self.mf.variables[var_name][start_index:end_index],
                        9e+36
                    )

                    if 'time' in group['dimensions']:
                        if y.count() > 0:
                            x = self.time[start_index:end_index]
                            ax.plot(x, y, marker='o', color=colors[j % len(colors)])
                    else:
                        ax.plot(y, marker='o', color=colors[j % len(colors)])

                elif dimensions == 2:
                    y = np.ma.masked_greater(
                        self.mf.variables[var_name][start_index:end_index][:,group['slice'][1]],
                        9e+36
                    )

                    if 'time' in group['dimensions']:
                        if y.count() > 0:
                            x = self.time[start_index:end_index]
                            ax.plot(x, y, marker='o', color=colors[j % len(colors)])
                    else:
                        ax.plot(y, marker='o', color=colors[j % len(colors)])

                else:
                    print('Not implemented')

            # xlabel
            if dimensions == 0:
                ax.set_xlabel('data point')
            elif dimensions == 1:
                ax.set_xlabel(group['dimensions'][0])
            elif dimensions == 2:
                ax.set_xlabel('{}, {}({})'.format(
                    group['dimensions'][0],
                    group['dimensions'][1],
                    str(self.mf.variables[group['dimensions'][1]][:][group['slice'][1]]) \
                        + ' ' + str(self.mf.variables[group['dimensions'][1]].units)
                ))
            else:
                print('Not implemented')

            ax.set_title(', '.join(var_names))

            if all('units' in self.mf.variables[x].ncattrs() for x in var_names):
                ax.set_ylabel(', '.join({self.mf.variables[x].units for x in var_names}))
                ax.legend(['{} ({})'.format(x, self.mf.variables[x].units) \
                    for x in var_names
                ])
            else:
                ax.set_ylabel('???')
                ax.legend(['{}'.format(x) \
                    for x in var_names
                ])

            ax.grid()

        plt.show()


# ----------------------------------------------------
# - Helper Methods -----------------------------------
# ----------------------------------------------------

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def lcm(a, b):
    return a * b // gcd(b, a)

def bin_search(a, d):
    first = 0
    last = len(a) - 1
    found = False
    m = -1
    
    while first <= last and not found:
        m = (first + last) // 2
        if a[m] == d:
            return m
        else:
            if a[m] > d:
                last = m - 1
            else:
                first = m + 1
    return m