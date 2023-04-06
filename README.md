# doe-dap-dl

This repository contains useful packages for Jupyter Notebook users to interact with data from A2e, Livewire, and the SPP data platform. Users will be able to import these packages and call high-level functions that handle all of the api calls, graphing, and interpolations to stream-line the end user's ability to analyze data.

### Example:

```python
from doe_dap_dl import DAP
a2e = DAP('a2e.energy.gov')

# authentication
a2e.setup_basic_auth(username='username', password='password')

# Search for files
filter = {
    'Dataset': 'wfip2/lidar.z04.a0',
    'date_time': {
        'between': ['20151004000000', '20151004020000']
    },
    'file_type': 'nc'
}

file_names = a2e.search(filter)

# download files
files = a2e.download_files(file_names)
```
