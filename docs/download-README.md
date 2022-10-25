# Downloads

## About
Method: `POST`

request-data facilitates search and download of data stored on A2e servers. Given a set of query parameters, request-data returns a mapping of file names to download URLs, which can later be used to download the requested files.

## Usage

### File Attributes
When a file is stored by the A2e system, a number of metadata attributes for that file are stored. request-data allows you to query on these attributes to retrieve specific data files. Along with values added by the system, the dot-delimited filename is parsed into attributes which can be used for data access. These attributes are named based on the configuration for the project. Arbitrary values that are not registered in the project config may also be stored in the file name. The first unregistered value will be stored as `ext1`, the second `ext2`, the third `ext3`, and so on.

### Output Format Parameters
Format parameters act as modifiers for the output of request-data, but do not effect the data query results.<br>
Valid format parameters are:

| Name          | Purpose       | Values|
| ------------- | ------------- | ----- |
| output        | Determines the format of the output filename-URL mapping. <ul><li>json - JSON dictionary of filenames to URLs</li><li>html - an HTML page with filename links that point to the download URL. If the `output` parameter isn't passed, this is the default mode</li><li>txt - A list of file URLs, delimited by newlines</li></ul>| json, html, txt |
| dryrun        | If the dryrun flag is present, the request will return file names, but download urls will not be generated | true, false |


### Query Parameters
Query parameters filter and control which data URLs are returned from request-data. A query parameter is an arbitrary key-value pair, where the key should be the name of a metadata attribute of one or more data files. Of the files with that metadata attribute, those which have a value matching the parameter value are returned. Query parameters can be [extended](#operators) with operations other than basic equality. All requests must have, at minimum, a Dataset parameter. Query parameters and their values are case sensitive. Every file has certain guaranteed parameters that are listed below:

<a name="param_table"></a>

| Name          | Explanation   | Example Values / Value Format|
| ------------- | ------------- | ----- |
| Dataset | Defined as the project name, a forward slash, and a dot-delimited list of every attribute in a data file name before the data date/time, the Dataset is required for every request. It is the broadest way to address a set of files with request-data | project/class.instance.level|
| data_date | The date parameter from the file name| YYYYMMDD |
| data_time | The time parameter from the file name| HHMMSS |
| date_time | The time and date parameters from the file name| YYYYMMDDHHMMSS |
| file_type | The extension of the file | txt, cdf, png |
| iteration | The version of the file | 0 1 2 |
| latest | A boolean that is set to True only for the latest iteration of the file | true, false |
| size | The size of the file in bytes | 30435 |

To find a full listing of the stored attributes for a given file or set of files, use the [get-info](../get-info/README.md) method.

### Creating Queries
To request data from request-data, you must create and POST a JSON document made up of query parameter key-value pairs. By default, basic equality is used to match documents, however, several advanced operators are supported. These operators can be applied to almost any attribute multiple times. The only exceptions are date_time, which can only filtered on once in a query, and Dataset, which cannot use special operators at all.

#### Basic Equality
A query that uses only basic single-value equality might look like this:
```json
{
	"output": "json",
	"filter": {
		"Dataset": "wfip2/lidar.z09.00",
		"data_date": "20160704",
		"file_type": "png"
	}
}
```
The output format is specified as JSON, each file attribute in the `filter` has a single string value that file metadata attribute values will have to match exactly.<br>This query will return all png images collected by the wfip2/lidar.z09.00 dataset on the fourth of July, 2016.<br>

#### Operators
Using operators from the table below, it is possible to extend the query syntax as follows in the example below, using the greater than operator and equals operator:
```json
{
	"output": "json",
	"filter": {
		"Dataset": "wfip2/lidar.z09.00",
		"file_type": "png",
		"data_date": {
			"gt": "20160704",
			"eq": "20160505"
		}
	}
}
```
The `data_date` value is now a JSON dictionary instead of a string. Each key in this dictionary should be an operation name, mapped to a value that the operation acts upon. The `gt` operation will be applied to the value `20160704`. The `eq` operation will be applied to the value `20160505`. The resulting query will now return all png images gathered by the wfip2/lidar.z09.00 dataset _after_ the fourth of July, 2016 and on the 5th of May, 2016.

Below is a table of supported operators:

| Operator      | Explanation   |
| ------------- | ------------- |
| begins_with   | The attribute must begin with the value|
| gt | The attribute must be greater than the value|
| gte | The attribute must be greater than or equal to the value|
| lt | The attribute must be less than the value|
| lte | The attribute must be less than or equal to the value |
| between | Requires a list of two values to be passed. The attribute must be between the two values (both the upper and lower bound are inclusive).|


#### Value Lists
It is possible to use a list of values anywhere that a single string value could be supplied. Instead of matching the single string, files matching any of the values in the list will be returned.
The query below shows the proper use of value lists:
```json
{
	"output": "json",
	"filter": {
		"Dataset": "wfip2/lidar.z09.00",
		"file_type": ["png", "txt"],
		"data_date": {
			"between": ["20160704", "20160707"],
			"eq": ["20160505", "20160405"]
		}
	}
}
```
The `file_type` attribute is expanded to match two possible values. `data_date` is filtered to match both a range of dates using the between operation, and two specific dates using the `eq` operation. The query will now match png and txt files that were gathered by the wfip2/lidar.z09.00 dataset from July 4th-7th, files from May 5th, and files from April 5th.

#### Optimization
Queries that filter on date_time can retrieve very specific ranges of data and will execute quickly. If your query involves time attributes, it can be beneficial to write the query to use the date_time attribute. Consider using a query like the following:
```json
{
	"data_time": {
		"between": ["20160505000000", "20160505240000"]
	}
}
```
instead of
```json
{
	"data_date": "20160505"
}
```
While both return the same file URLs, the first will execute much more quickly.

## Example
```python
# Get a JSON blob of URLs of image files stored by the wfip2/lidar.z09.00 Dataset in a 48 hour period
import json
import base64
import requests

api_url = 'https://l77987ttq5.execute-api.us-west-2.amazonaws.com/prod'

# Prepare auth header
auth = {
    "Authorization": "Basic {}".format(base64.b64encode(
	("{}:{}".format("guest", "guest")).encode("utf-8")
    ).decode("ascii"))
}

params = {
    "output": "json",
    "filter": {
        "Dataset": "wfip2/lidar.z09.00",
        "file_type": ["png", "gif", "jpeg"],
        "date_time": {
        	"between": ["20160505000000", "20160507000000"]
    	}
    }
}

req = requests.post("{}/downloads".format(api_url), headers=auth, data=json.dumps(params))
print(req.text)
```
