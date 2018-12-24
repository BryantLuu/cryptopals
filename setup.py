from setuptools import setup

setup(
    name="crypto",
    author="Bryant",
    install_requires=[
        "awscli", "boto3", "flake8", "joblib", "pandas>=0.23.4", "psycopg2",
        "pylint==1.7.4", "python-dotenv", "requests", "progressbar", "sklearn",
        "tqdm", "ujson", "web3", "sendgrid==5.6.0", "pypd", "premailer",
        "jinja2", "botocore>=1.12.38", "scipy", "pycrypto", "ipdb"
    ],
    packages=["crypto"])
