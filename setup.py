from setuptools import setup, find_packages

setup(
    name="netsec-auditor",
    version="1.0.0",
    description="Production-grade network security assessment tool",
    author="Security Engineering Team",
    python_requires=">=3.9",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "netsec-auditor=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
