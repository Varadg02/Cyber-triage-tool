from setuptools import setup, find_packages

setup(
    name="cyber-triage-tool",
    version="0.1.0",
    description="Cyber triage tool with automated analysis and one-click investigation",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "cyber-triage=main:main",
        ]
    },
)

