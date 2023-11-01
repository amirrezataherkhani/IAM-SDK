import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="iam",
    version="0.0.15",
    author="VisaPick Group",
    author_email="Visapick.it@gmail.com",
    description="IAM package",
    keywords="auth, pypi, package, utills",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Visapick-Team/IAM-SDK",
    install_requires=[
        "pyjwt",
        "bar",
        "greek",
        "python-jose",
        "cryptography",
        "passlib",
        "fastapi",
        "pydantic",
        "djangorestframework",
        "django",
        "djangorestframework",
    ],
    packages=["iam"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    extras_require={
        "dev": ["check-manifest"],
        # 'test': ['coverage'],
    },
)
