from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

with open("README.md", "r", encoding="utf-8") as f:
    readme = f.read()

setup(
    name="dispatch-py",
    version="0.1.0",
    description="A SOCKS proxy that balances traffic between network interfaces",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/tboy1337/dispatch-py",
    download_url="https://github.com/tboy1337/dispatch-py/releases/latest",
    author="tboy1337",
    author_email="obywhuie@anonaddy.com",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "dispatch=dispatch.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
) 