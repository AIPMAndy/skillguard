from setuptools import setup

from safeskill import __version__

setup(
    name="safeskill",
    version=__version__,
    description="Skill Security Scanner - Focus on securing AI Skills",
    author="AIPMAndy",
    author_email="",
    url="https://github.com/AIPMAndy/safeskill",
    py_modules=["safeskill"],
    install_requires=["PyYAML>=6.0"],
    extras_require={
        "dev": ["pytest>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "safeskill=safeskill:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="security scanner skill ai safety",
    license="Apache-2.0",
)
