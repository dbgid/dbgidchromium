from pathlib import Path
import re

from setuptools import setup


ROOT = Path(__file__).resolve().parent
INIT_FILE = ROOT / "__init__.py"
README_FILE = ROOT / "README.md"


def read_version():
    content = INIT_FILE.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        raise RuntimeError("Unable to find __version__ in __init__.py")
    return match.group(1)


setup(
    name="dbgidchromium",
    version=read_version(),
    description="Android-focused browser automation toolkit",
    long_description=README_FILE.read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="dbgid",
    url="https://github.com/dbgid/dbgidchromium",
    project_urls={
        "Repository": "https://github.com/dbgid/dbgidchromium",
        "Required Browser": "https://github.com/dbgid/DBG-ID-Browser",
    },
    license="MIT",
    python_requires=">=3.10",
    packages=["dbgidchromium"],
    package_dir={"dbgidchromium": "."},
    package_data={"dbgidchromium": ["ip2asn-v4-u32.tsv"]},
    include_package_data=True,
)
