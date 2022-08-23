# Dap_py Package

This package contains the dap_py module and wraps all other packages to make importing easy. Information on the plotting module is in plot/README.md. For more information on the dap_py module, keep reading.

## Dap_py Module

The dap_py module is a high-level interface that allows the programmer to use our API to authenticate, search, and download the data they want in very few lines of code.

## Setup

The following examples demonstrate how to download data via A2e.

First, import the module:

```python
from dap_py import dap
```

Then, create an instance of the `dap` class. The constructor takes one required argument: the hostname of the service from which you want to download data.

```python
a2e = dap('a2e.energy.gov')
```

And that's it! Setup is complete. All future methods will revolve around this `a2e` object. Alternatively, the constructor accepts two optional arguments: `cert` and `quiet`. The cert argument takes the path to a certificate. The quiet argument disables output when set to `True`, which is useful for scripting.

## Authentication

Authentication is simple. This module supports both __basic__ and __certificate__ authentication protocols. The basic method does not use a certificate, expires more quickly, and does not support two-factor authentication. The other methods in this module will not work without proper authentication. If a path to a certificate is not provided, the constructor will attempt to find a certificate named `.<host name>.cert` in the top-level dap-py directory.

Providing a path to an existing certificate to dap:

```python
a2e = dap('a2e.energy.gov', '/path/to/a2e.energy.gov.cert')
```

If the certificate is valid, the module will renew it. Otherwise, the constructor will set up guest credentials. If you don't have a valid certificate, you will have to create one via one of the following authentication methods:

#### `a2e.setup_basic_auth(username=None, password=None)`

Sets up basic authentication with a username and password. The arguments are optional, but the module will prompt for them if omitted.

#### `a2e.setup_cert_auth(username=None, password=None)`

Similar to the method above, but will request a certificate instead of basic authentication. The certificate is stored in a file named `.<host name>.cert`, for example `.a2e.energy.gov.cert`.

#### `a2e.setup_two_factor_auth(username=None, password=None, authcode=None)`

Similar to the method above, but uses two-factor authentication. The authcode is the 6-digit password code from Google Authenticator. This is the highest authentication level available. The again stores the certificate in a `.<host name>.cert` file.

### Searching for Files

To search for files, one must first construct a filter. Below is an example filter.

```python
filter = {
    'Dataset': 'wfip2/lidar.z01.b0',
    'date_time': {
        'between': ['20160101000000', '20160104000000']
    },
    'file_type': 'nc'
}
```
The documentation for constructing the filter argument can be found [here](https://github.com/a2edap/dap-py/blob/master/a2e/download-README.md).

Now simply call this function:

#### `a2e.search(filter_arg, table='inventory', latest=True)`

The `'inventory'` option returns a list of files that match the filter. Filters that return large lists of files may time out. To avoid this, you can request an accounting of files by calling the function with `table='stats'`.

By default, only the latest files are considered for the search. If you'd like to include older files, you can use `latest=False`. Old files may not be downloadable.


### Downloading Files

There are three functions you can use to download files using this module.

#### Download with a list of files

An inventory search returns a list of files. These can be provided to the following function:

#### `a2e.download_files(files, path='/var/tmp/', replace=False)`

The path specifies where the module will download files. The replace flag determines whether the module should replace files that already exist in the download directory. By default, the module will not replace existing files.

##### Example

```python
filter = {
    'Dataset': 'wfip2/lidar.z04.a0',
    'date_time': {
        'between': ['20151001000000', '20151004000000']
    },
    'file_type': 'nc'
}

file_names = a2e.search(filter, table='Inventory')
files = a2e.download_files(file_names)
```

All the download functions return a list of paths to the downloaded files.

#### Download files directly from a search

Inventory searches fail with large numbers of files. This method will avoid creating a list of files and instead download using a search query. The module will prompt you to confirm that you want to download the files, although it won't say how much space the files will take up, so caution is recommended.

The dap function is:
#### `a2e.download_search(filter_arg, path='/var/tmp/', force=False)`

##### Example

```python
filter = {
    'Dataset': 'wfip2/lidar.z04.a0',
    'date_time': {
        'between': ['20151001000000', '20151004000000']
    },
    'file_type': 'nc'
}

files = a2e.download_search(filter)
```

Provided with a [filter argument](https://github.com/a2edap/dap-py/blob/master/a2e/download-README.md), search the Inventory table and download the files in s3. I heard a rumor through the grapevine that only files in s3 will be downloaded, so if you think some data could be someone else, use the next download method.

#### Download by placing an order

Placing an order is required to download files that are not in s3. The following function takes a filter like `download_search()` but places an order before downloading.

#### `a2e.download_with_order(filter_arg, path='/var/tmp/', force=False)`

Like `download_search()`, the code will prompt you to confirm that you want to download the files.

```python
filter = {
    'Dataset': 'wfip2/lidar.z04.a0',
    'date_time': {
        'between': ['20151001000000', '20151004000000']
    },
    'file_type': 'nc'
}

a2e.download_with_order(filter)
```
