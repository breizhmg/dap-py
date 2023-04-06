import re
import requests
import json


def get_api_url(host_URL):
    """
    Returns the data API url from a DAP host URL by scrapping DAP client responses

    Args:
        host_URL (str): the url of the host, e.g. "livewire.energy.gov"
    """
    # get data page html contents
    if not host_URL.startswith("http"):
        host_URL = f"http://{host_URL}"
    req = requests.get(f"{host_URL}/data")

    data_html = req.text

    # extract main.xxxxxxxx.chunk.js from response
    main_js = re.search(r'"[^<>]*main\..*\.chunk.js"', data_html)[0]
    main_js_url = f"{host_URL}{main_js[1:-1]}"

    # get js file contents:
    req = requests.get(main_js_url)
    main_js_contents = req.text

    # extract prod URL
    prod_json_str = (
        "{" + re.search(r'"prod":\s*{[^}]*}', main_js_contents).group() + "}"
    )
    prod_json = json.loads(prod_json_str)
    return prod_json["prod"]["lambdaApi"]
