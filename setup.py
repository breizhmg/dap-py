import os
import pathlib
import setuptools

# The directory containing this file
CWD = pathlib.Path(__file__).parent

# The text of the README file
README = (CWD / "README.md").read_text()

# Get the list of dependencies from the requirements.txt file
with open(os.path.join(CWD, "requirements.txt")) as requirements_file:
    # Parse requirements.txt, ignoring any commented-out lines.
    REQUIREMENTS = [
        line for line in requirements_file.read().splitlines() if not line.startswith("#")
    ]

version = "0.1.0"
assert "." in version

setuptools.setup(
    name="doe-dap-dl",
    version=version,
    description="Packages for Jupyter Notebook users to interact with data from A2e, Livewire, and the SPP data platform.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/DAP-platform/dap-py",
    author="DAP-Platform",
    author_email="dapteam@pnnl.gov",
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Scientific/Engineering",
        "Intended Audience :: Science/Research",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(exclude=["docs", "tests", "examples"]),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIREMENTS,
    scripts=[],
)
