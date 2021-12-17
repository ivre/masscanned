# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

from ast import literal_eval
import configparser
import os

# -- Path setup --------------------------------------------------------------

# -- Project information -----------------------------------------------------

project = "IVRE"
copyright = "2021, The IVRE project"
html_logo = "img/logo.png"
master_doc = "index"

def parse_cargo():
    config = configparser.ConfigParser()
    config.read(os.path.join("..", "Cargo.toml"))
    if "package" not in config:
        return None, None, None
    package = config["package"]
    try:
        author = literal_eval(package.get("authors"))[0].split("<", 1)[0].strip()
    except KeyError:
        authors = None
    return literal_eval(package.get("name")), author, literal_eval(package.get("version"))

project, author, version = parse_cargo()

# -- General configuration ---------------------------------------------------

extensions = []

autosectionlabel_prefix_document = True

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"
