from setuptools import setup, find_packages

setup(
    name="skillguard",
    version="0.2.0",
    description="Skill Security Scanner - Focus on securing AI Skills",
    author="AIPMAndy",
    author_email="",
    url="https://github.com/AIPMAndy/skillguard",
    py_modules=["skillguard"],
    entry_points={
        "console_scripts": [
            "skillguard=skillguard:main",
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
