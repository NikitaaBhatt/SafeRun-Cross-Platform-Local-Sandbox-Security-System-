from setuptools import setup, find_packages
import os

def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, encoding="utf-8") as f:
            return f.read()
    return ""

setup(
    name="saferun",
    version="0.1.0",
    packages=find_packages(exclude=["tests*", "venv*", "build*", "dist*"]),
    include_package_data=True,

    install_requires=[
        "PyQt6==6.8.1",
        "docker==7.0.0",
        "psutil==5.9.8",
        "pyyaml==6.0.1",
        "requests==2.32.0",
        "pandas==2.2.2",
        "numpy>=1.26.0,<2.1.0",
        "scikit-learn==1.5.0",
        "cryptography==44.0.1",
        "pillow==10.3.0",
    ],

    entry_points={
        "console_scripts": [
            "saferun=saferun.main:main",
        ],
    },

    author="CodeCrafters Team",
    author_email="nikkitabhatt1020@gmail.com",
    description="Cross-Platform Local Sandbox Security System",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    keywords="security, sandbox, containerization, malware-detection",
    python_requires=">=3.10, <3.12",

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],

    extras_require={
        "dev": [
            "pytest==8.1.1"
        ]
    }
)
