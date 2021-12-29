import json
import json2html
from json2html import *
from jinja2 import Environment, FileSystemLoader


class Json_To_HTML:
    with open('cve_collections_for_all_programs.json') as f:
        d = json.loads(f.read())
        scanOutput = json2html.convert(json=d)
        htmlReportFile = "templates/scanner.html"
        with open(htmlReportFile, 'w') as htmlfile:
            htmlfile.write(str(scanOutput))
            print("json file id converted into html successfully....")

# fileLoader = FileSystemLoader("templates")
# env = Environment(loader=fileLoader)
#
