from setuptools import setup, find_packages

setup(
    name="insightlog",
    version="1.0.0",
    description="Linux Security Monitoring & Incident Response Tool",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "insightlog=insightlog.cli:main",
            "insightlog-gui=insightlog.gui:main",
        ],
    },
    python_requires=">=3.8",
    install_requires=[],
)