from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="unified-webhook-router",
    version="1.0.0",
    author="",
    description="A unified webhook router for handling webhooks from multiple providers (Stripe, GitHub, Slack, etc.)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/unified-webhook-router",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    keywords="webhook stripe github slack twilio square router verification",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/unified-webhook-router/issues",
        "Source": "https://github.com/yourusername/unified-webhook-router",
    },
)