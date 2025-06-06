from setuptools import setup, find_packages

setup(
    name="assessment-platform",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "flask==3.0.0",
        "flask-cors==4.0.0",
        "gunicorn==21.2.0",
    ],
)
