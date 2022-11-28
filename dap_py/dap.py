import os
import json
import base64
from pathlib import Path
import requests
from getpass import getpass
from .utils.scraper import get_api_url


class BadStatusCodeError(RuntimeError):
    def __init__(self, req):
        self.status_code = req.status_code
        try:
            self.reason = req.json()["message"]
        except (KeyError, ValueError):
            self.reason = req.reason

    def __str__(self):
        return (
            "Server Returned Bad Status Code\n"
            f"Status Code: {self.status_code}\n"
            f"Reason: {self.reason}"
        )


class DAP:
    def __init__(
        self,
        host_URL,
        cert_path=None,
        save_cert_dir=str(Path.home() / "dap/certs/"),
        download_dir=str(Path.home() / "dap/downloads"),
        quiet=False,
        spp=False,
        confirm_downloads=True,
    ):
        """initializes connection with DAP server and performs authentication

        Args:
            host_URL (str): The url of the host, e.g. "livewire.energy.gov"
            cert_path (str, optional): path to authentication certificate file. Defaults to None.
            save_cert_dir (str, optional): Path to directory where certificates are stored. Defaults to ~/dap/certs/
            download_dir (str, optional): Path to directory where files will be downloaded. Defaults to ~/dap/downloads/
            quiet (bool, optional): suppresses output print statemens. Useful for scripting Defaults to False.
            spp (bool, optional): If this is a dap for the Solid Phase Processing data. Defaults to False.
            confirm_downloads (bool, optional): Whether or not to confirm before downloading. Defaults to True.
        """
        self.host_URL = host_URL
        if spp:
            self._api_url = (
                "https://13tl7mor8f.execute-api.us-west-2.amazonaws.com/prod"
            )
        else:
            self._api_url = get_api_url(self.host_URL)

        self._quiet = quiet
        self.confirm_downloads = confirm_downloads
        self._cert_path = cert_path
        self._cert = None
        self._auth = None

        # set the certificate and download paths.
        if "DAP_CERT_DIR" in os.environ:
            self.save_cert_dir = os.environ["DAP_CERT_DIR"]
        else:
            self.save_cert_dir = save_cert_dir

        if "DAP_DOWNLOAD_DIR" in os.environ:
            self.download_dir = os.environ["DAP_DOWNLOAD_DIR"]
        else:
            self.download_dir = download_dir

        self.__create_dirs()

        self.__read_cert()

        if self.__cert_is_valid():
            self.__create_cert_auth()
            self.__print("Certificate is setup")
        else:
            self.setup_guest_auth()
            self.__print(
                "Certificate not found or was invalid. Using guest credentials..."
            )

    def __print(self, *args, sep="", end="\n", file=None):
        if not self._quiet:
            for arg in args:
                print(arg, sep=sep, end=end, file=file)

    def __create_dirs(self):
        Path(self.save_cert_dir).mkdir(parents=True, exist_ok=True)
        Path(self.download_dir).mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------------
    # Getting Authenticated
    # --------------------------------------------------------------

    def __request_cert(self, params):
        """Request a certificate"""
        req = requests.put(f"{self._api_url}/creds", params=params)

        if req.status_code != 200:
            raise BadStatusCodeError(req)

        self._cert = json.loads(req.text)["cert"]
        self.__save_cert()

    def __create_cert_auth(self):
        """Given an existing certificate, create an auth token"""
        if not self._cert:
            raise ValueError("cert cannot be None")

        encoded_cert = base64.b64encode(self._cert.encode("utf-8")).decode("ascii")
        self._auth = {"Authorization": f"Cert {encoded_cert}"}

    def __request_cert_auth(self, params):
        """Requests certificate and creates auth token"""
        try:
            self.__request_cert(params)
            self.__create_cert_auth()
        except BadStatusCodeError:
            self.__print("Incorrect credentials")
            return
        except Exception as e:
            self.__print(e)
            return
        self.__print("Success!")
        return True

    def setup_basic_auth(self, username=None, password=None):
        """Create an auth token without a certificate

        Args:
            username (str, optional): Username, if None it will prompt. Defaults to None.
            password (str, optional): Password, if None it will prompt. Defaults to None.
        """

        username = username or input("username: ")
        password = password or getpass("password: ")

        user_pass_encoded = base64.b64encode(
            (f"{username}:{password}").encode("utf-8")
        ).decode("ascii")

        self._auth = {"Authorization": f"Basic {user_pass_encoded}"}
        # TODO: check if the creds are valid
        # without a certificate
        # should we try a query? low priority

    def setup_guest_auth(self):
        """Set up basic auth as a guest"""
        self.setup_basic_auth("guest", "guest")

    def setup_cert_auth(self, username=None, password=None):
        """Given username and password request a cert token and generate a
           certificate

        Args:
            username (str, optional): Username, if None it will prompt. Defaults to None.
            password (str, optional): Password, if None it will prompt. Defaults to None.

        Returns:
            bool: Whether the requested certificate was valid.
        """
        if self.__cert_is_valid():
            self.__print("Valid certificate already created")
            return True

        params = {
            "username": username or input("username: "),
            "password": password or getpass("password: "),
        }
        try:
            self.__request_cert_auth(params)
        except BadStatusCodeError:
            self.__print("")
            return False
        return self.__cert_is_valid()

    def setup_two_factor_auth(self, username=None, password=None, authcode=None):
        """Given a username, password, and 2 factor authentication code,
           generate a certificate with two factor auth permissions

        Args:
            username (str, optional): Username, if None it will prompt. Defaults to None.
            password (str, optional): Password, if None it will prompt. Defaults to None.
            authcode (str, optional): Two factor auth code, if None it will prompt. Defaults to None.

        Returns:
            bool: Whether the requested certificate was valid.
        """
        # we can't tell what kind of certification they
        # have with our current API, so we'll just make
        # them a new one

        params = {
            "username": username or input("username: "),
            "password": password or getpass("password: "),
            "authcode": authcode or getpass("authcode: "),
        }

        self.__request_cert_auth(params)
        return self.__cert_is_valid()

    def __renew_cert(self):
        """Renews the certificate"""
        if not self._cert:
            raise ValueError("No certificate to renew")

        params = {
            "cert": self._cert,
            "action": "renew",
        }

        resp = requests.put(f"{self._api_url}/creds", params=params)

        if resp.status_code != 200:
            raise BadStatusCodeError(resp)

        return "cert" in resp.json()

    def __cert_is_valid(self):
        try:
            return self.__renew_cert()
        except (ValueError, BadStatusCodeError) as e:  # noqa: E722
            return False

    def __save_cert(self):
        """Save the cert to path"""
        if self._cert_path is not None:
            with open(self._cert_path, "w") as cf:
                cf.write(self._cert)
                self.__print(f"Saved certificate as {self._cert_path}")

    def __read_cert(self):
        """Read from the path"""
        if self._cert_path is None:
            # check for a cert in the save directory
            self._cert_path = Path(self.save_cert_dir) / f".{self.host_URL}.cert"
            self.__print(f"Looking for a certificate: {self._cert_path}...")
        try:
            with open(self._cert_path) as cf:
                self.__print(f"Found certificate: {self._cert_path}")
                self._cert = cf.read()
        except FileNotFoundError:
            self.__print(f"File not found {self._cert_path}")
            return False
        return True

    # --------------------------------------------------------------
    # Search for Filenames
    # --------------------------------------------------------------

    def search(self, filter_arg, table="inventory", latest=True):
        """Search the table and return the matching file information

        Args:
            filter_arg (dict): The filter argument. For information on how to construct this see download-README.md
            table (str, optional): Which table to query. Either 'inventory' or 'stats'. Defaults to 'inventory'.
            latest (bool, optional): Whether to only include the latest files. Defaults to True.

        Returns:
            list: The list of file information returned by the filter.
        """

        if not self._auth:
            raise Exception("Auth token cannot be None")

        if "livewire" not in self.host_URL:
            filter_arg["latest"] = latest

        if "test" in self.host_URL and not table.endswith("-test"):
            self.__print(
                "You're trying to access data on a test server, but the table name doesn't include 'test', adding it."
            )
            table += "-test"

        # the dataset can be the only key in the filter
        if "test" in self.host_URL and len(filter_arg.keys()) > 1:
            if "Dataset" in filter_arg.keys():
                self.__print(
                    "A dataset can be the only parameter in the filter for a test server, removing the extras."
                )
                filter_arg = {"Dataset": filter_arg["Dataset"]}
            else:
                self.__print("No dataset provided.")
                return

        req = requests.post(
            f"{self._api_url}/searches",
            headers=self._auth,
            data=json.dumps(
                {
                    "source": table,
                    "output": "json",
                    "filter": filter_arg
                    # 'with_inv_stats_beyond_limit':True
                }
            ),
        )
        req.raise_for_status()

        return req.json()

    # --------------------------------------------------------------
    # Placing Orders
    # --------------------------------------------------------------

    def __place_order(self, dataset, filter_arg):
        """Place an order and return the order ID"""
        if not self._auth:
            raise Exception("Auth token cannot be None")

        params = {"datasets": {f"{dataset}": {"query": filter_arg}}}

        req = requests.put(
            f"{self._api_url}/orders", headers=self._auth, data=json.dumps(params)
        )

        if req.status_code != 200:
            raise BadStatusCodeError(req)

        ID = json.loads(req.text)["id"]
        return ID

    # --------------------------------------------------------------
    # Getting download URLs
    # --------------------------------------------------------------

    def __get_download_urls(self, ID, page_size=500):
        """Given order ID, return the download urls"""
        if not self._auth:
            raise Exception("Auth token cannot be None")

        urls = []
        cursor = None

        while True:
            try:
                new_urls, cursor = self.__get_page_of_download_urls(
                    ID, page_size, cursor
                )
            except BadStatusCodeError as e:
                self.__print("Error getting page of download urls!")
                self.__print(e)

            urls.extend(new_urls)
            self.__print(f"Added {len(new_urls)} urls.")

            if cursor is None:
                self.__print(
                    f"No more pages of files, stopping after {len(urls)} urls."
                )
                return urls

            self.__print("Another page detected, continuing...\n")

    def __get_page_of_download_urls(self, ID, page_size, cursor=None):
        """Return one page of download urls given the order id, cursor and page size"""
        cursor_param = "" if cursor is None else f"&cursor={cursor}"

        # self._print(f"cursor param: {cursor_param}")

        req = requests.get(
            f"{self._api_url}/orders/{ID}/urls?page_size={page_size}{cursor_param}",
            headers=self._auth,
        )

        if req.status_code != 200:
            raise BadStatusCodeError(req)

        response = json.loads(req.text)
        urls = response["urls"]
        cursor = response["cursor"]

        return urls, cursor

    # --------------------------------------------------------------
    # Download from URLs
    # --------------------------------------------------------------

    def __download(self, url, path):
        """Actually download the files"""
        req = requests.get(url, stream=True)
        if req.status_code != 200:
            raise BadStatusCodeError(req)
        while True:  # is this needed?
            with open(path, "wb") as fp:
                for chunk in req.iter_content(chunk_size=1024):
                    fp.write(chunk)
            self.__print(f"Download successful! {path}")
            break

    def __download_from_urls(self, urls, path="/var/tmp/", replace=False):
        """Given a list of urls, download them
        Returns the successfully downloaded file paths
        """
        if not urls:
            raise Exception("No urls provided")

        downloaded_files = []
        self.__print(f"Attempting to download {len(urls)} files...")
        # TODO: multi-thread this
        for url in urls:
            try:
                a = url.split("/")
                filename = a[5].split("?")[0]

                download_dir = path
                os.makedirs(download_dir, exist_ok=True)
                # the final file path
                filepath = os.path.join(download_dir, filename)
            except:
                self.__print(f"Incorrectly formmated file path in url: {url}")
                continue

            if not replace and os.path.exists(filepath):
                self.__print(f"File: {filepath} already exists, skipping...")
            else:
                try:
                    self.__download(url, filepath)
                except BadStatusCodeError as e:
                    self.__print(f"Could not download file: {filepath}")
                    self.__print(e)
                    continue

            downloaded_files.append(filepath)

        self.__print(f"Downloaded {len(downloaded_files)} files!")

        return downloaded_files

    # --------------------------------------------------------------
    # Place Order and Download
    # --------------------------------------------------------------

    def download_files(self, files, path="/var/tmp/", replace=False):
        """Download a list a files

        Args:
            files (list): A list of files obtained via search()
            path (str, optional): The download path. Defaults to "/var/tmp/".
            replace (bool, optional): Whether to redownload and replace existing files. Defaults to False.

        Returns:
            list: The list of paths to the downloaded files.
        """
        if not files:
            self.__print("No files provided.")

        if not self._auth:
            raise Exception(
                "Auth token cannot be None. It can be updated with setup_cert_auth()"
            )

        filter = {
            "output": "json",
            "filter": None,
        }

        urls = []
        found = 0
        not_found = 0
        for f in files:
            filename = f["Filename"]

            filter["filter"] = f

            req = requests.post(
                f"{self._api_url}/downloads",
                headers=self._auth,
                data=json.dumps(filter),
            )

            req.raise_for_status()

            url = json.loads(req.text)["urls"].values()

            # this should only return one url
            if len(url) != 1:
                self.__print(
                    f"found {len(url)} urls instead of one for file {filename}"
                )
                not_found += 1
            else:
                self.__print(f"found url for file: {filename}")
                found += 1

            # use extend in case somehow multiple files were found, this might not be necessary
            urls.extend(url)

        self.__print(f"found {found} files.")
        if not_found > 0:
            self.__print(
                f"Urls could not be found for {not_found} files, these files are most likely not hosted on s3 and should be downloaded via download_with_order()."
            )

        download = True
        if self.confirm_downloads:
            download = self.__proceed_prompt(f"Download {len(urls)} files (y/n)? ")

        if not download:
            return
        try:
            return self.__download_from_urls(urls, path=path, replace=replace)
        except Exception as e:
            self.__print(e)

    # --------------------------------------------------------------
    #  Download All matching Search
    # --------------------------------------------------------------

    def __search_for_urls(self, filter_arg):
        """uses the alternative api /downloads method
        to search the inventory table and return
        the download urls to files in s3
        """
        if not self._auth:
            raise Exception("Auth token cannot be None")

        req = requests.post(
            f"{self._api_url}/downloads",
            headers=self._auth,
            data=json.dumps(filter_arg),
        )

        if req.status_code != 200:
            raise BadStatusCodeError(req)

        urls = json.loads(req.text)["urls"].values()
        return urls

    def download_search(self, filter_arg, path="/var/tmp/", replace=False):
        """Download files straight from a search without placing an order

        Args:
            filter_arg (dict): The filter argument. For information on how to construct this see download-README.md
            path (str, optional): The download path. Defaults to '/var/tmp/'.
            replace (bool, optional): Whether to redownload and replace existing files. Defaults to False.

        Returns:
            list: The list of paths to the downloaded files.
        """

        try:
            urls = self.__search_for_urls(
                {
                    "output": "json",
                    "filter": filter_arg,
                }
            )
        except BadStatusCodeError as e:
            self.__print("Could not find download urls")
            self.__print(e)
            return
        except Exception as e:
            self.__print(e)
            return

        if not urls:
            self.__print("No files found")
            return

        download = True
        if self.confirm_downloads:
            download = self.__proceed_prompt(f"Download {len(urls)} files (y/n)? ")

        if download:
            try:
                downloaded_files = self.__download_from_urls(
                    urls, path=path, replace=replace
                )
            except Exception as e:
                self.__print(e)
                return
        else:
            return

        return downloaded_files

    def download_with_order(self, filter_arg, path="/var/tmp", replace=False):
        """Place an order and download files based on a query.

        filter_arg (dict): The filter argument. For information on how to construct this see download-README.md
        path (str, optional): The download path. Defaults to '/var/tmp/'.
        replace (bool, optional): Whether to redownload and replace existing files. Defaults to False.

        Returns:
            list: The list of paths to the downloaded files.
        """
        dataset = filter_arg["Dataset"]

        if not dataset:
            raise Exception("No dataset provided!")

        self.__print("Attempting to place an order for the data...")

        try:
            ID = self.__place_order(dataset, filter_arg)
        except BadStatusCodeError as e:
            self.__print("Could not place order")
            self.__print(e)
            return

        self.__print(f"Order placed! ID: {ID}")
        self.__print("Attempting to fetch download urls...")

        try:
            urls = self.__get_download_urls(ID)
        except BadStatusCodeError as e:
            self._print("Could not get download urls")
            self._print(e)
            return

        self.__print("Urls found!")

        download = True
        if self.confirm_downloads:
            download = self.__proceed_prompt(f"Download {len(urls)} files (y/n)? ")

        if download:
            try:
                downloaded_files = self.__download_from_urls(
                    urls, path=path, replace=replace
                )
            except Exception as e:
                self._print(e)
                return
        else:
            return

        return downloaded_files

    def __proceed_prompt(self, prompt):
        while True:
            proceed = input(prompt)
            if proceed.lower() not in ("y", "n"):
                print("Enter either y or n")
            else:
                break

        return proceed == "y"
