"""Phantom - LLM Red Teaming & Jailbreak Testing Platform."""

from setuptools import setup, find_packages

setup(
    name="phantom",
    version="0.1.0",
    description="LLM Red Teaming & Jailbreak Testing Platform",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Phantom Team",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,
    install_requires=[
        "click>=8.1",
        "rich>=13.0",
        "flask>=3.0",
        "flask-cors>=4.0",
        "requests>=2.31",
        "httpx>=0.27",
        "aiohttp>=3.9",
        "openai>=1.0",
        "anthropic>=0.25",
        "jinja2>=3.1",
        "pyyaml>=6.0",
        "sqlite-utils>=3.36",
        "plotly>=5.18",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-asyncio>=0.23",
            "pytest-cov>=4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "phantom=ui.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
