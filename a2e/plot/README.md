# a2e.plot Package

This package contains the plot module. The package requires both matplotlib and numpy as dependencies apart from the standard python core library.

## plot Module

This module is useful for plotting different variables against each other using matplotlib in just one line of code. This is designed for users who just want to see their data and run simple analysies.

## Setup

First, import the module. If using Jupyter Notebook, be sure to use the iPython magic `%` to setup matplotlib:

```python
%matplotlib inline
from a2e.plot import plot
```

Next, create a Plotter object:

```python
plotter = plot.Plotter('/var/tmp/wfip2.lidar.z01.b0/')
```

And that's it. Create plots using the `plot` function.

### Plotting

After setting up the plotter, just call the `plot` function. The function signature is provided here:

#### `plotter.plot(variable_groups, begin=None, end=None, width=18, height=6)`

##### `variable_groups`

The only required argument is the variable_groups 2D array. This array contains a list of lists of regular expressions. The 2D array is used so the user can group different variables on one plot, as long as it shares the same data shape provided from the netCDF files.

##### `begin`

Datetime object specifying the beginning of the plot.

##### `end`

Datetime object specifying the end of the plot.

##### `width`

Width of each plot in inches.

##### `height`

Height of each plot in inches.

## Example

```python
%matplotlib inline
from a2e.plot import plot

plotter = plot.Plotter('/var/tmp/wfip2.lidar.z01.b0/')

plotter.plot([
    ['wind_u$', 'wind_v$', 'vertical_air_velocity$'],
    ['height$'],
    ['time$']
])
```