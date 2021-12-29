import csv
import json
import pathlib
from csv import reader
from pprint import pformat

import pandas as pd
import datetime

import cve_parser
import searchEngine

class Cve_Of_Regisrty:
    All_CVE = []

    def get_cpe23name_of_programs(self):
        list_cpe23name = []
        dataframe = pd.read_csv('retrieved_cosin.csv')
        for index, row in dataframe.iterrows():
            if row["sim_score"] > 0.6:
                list_cpe23name.append(row["cpe_23_names"])
        # list_cpe23name = dataframe[]
        return list_cpe23name


    # def scan_cve(cpe23name):
    #     cve = cve_parser.CveParser()
    #     list_of_all_cve_of_cpe23name = []
    #     # for year in range( datetime.date.today().year, 2001, -1):
    #     year = 2021
    #     cve_parser.CveParser.write_all_cve_collection_for_specific_year_to_file(cve, str(year))
    #     with open('cve_collections_for_%s.json' % (str(year))) as data_file:
    #         data = json.load(data_file)
    #         for cve in data:
    #             cpe_match = cve['cpe_match']
    #             for cpe in cpe_match:
    #                 if cpe['cpe23Uri'] == cpe23name:
    #                     list_of_all_cve_of_cpe23name.append(cve)
    #     seen = []
    #     output_cpe23name = []
    #     for d in list_of_all_cve_of_cpe23name:
    #         if d['identifier'] not in seen:
    #             output_cpe23name.append(d)
    #             seen.append(d['identifier'])
    #     return output_cpe23name

    def scan_cve(self, list_of_cpe23name):
        cve = cve_parser.CveParser()
        list_of_all_cve_of_cpe23name = []
        for year in range(datetime.date.today().year, 2001, -1):
        # year = 2021
            list_of_cve_year = cve_parser.CveParser.get_cve_collection_for_specific_year(cve, str(year))
            for cve_i in list_of_cve_year:
                cpe_match = cve_i.cpe_match
                for cpe in cpe_match:
                    if cpe['cpe23Uri'] in list_of_cpe23name:
                        list_of_all_cve_of_cpe23name.append(cve_i)
        seen = []
        output_cve_of_cpe23name = []
        for d in list_of_all_cve_of_cpe23name:
            if d.identifier not in seen:
                output_cve_of_cpe23name.append(d)
                seen.append(d.identifier)
        return output_cve_of_cpe23name

        # for cve in
        # print(cve_parser.CveParser.get_cve_collection_for_specific_year(cve, str(2021)))
    def json_of_all_cve_in_registry(self, list_of_cve):
        json_object = json.dumps(list_of_cve, indent=4)
        with open("All_cve.json" , "w") as outfile:
            outfile.write(json_object)
        return list_of_cve


    # def cve_for_all_program(self):
    #     filename = 'retrieved_cosin.csv'
    #     df = pd.read_csv(filename)
    #
    #     for index, cpe in df.iterrows():
    #         list_of_all_cve = []
    #         if cpe['sim_score'] >= 0.6:
    #             list_of_all_cve += scan_cve(cpe['cpe_23_names'])
    #     return list_of_all_cve
    #

def write_cve_of_programs_to_json(list_of_cve):
    cve_json_collection = []
    for cve in list_of_cve:
        cve_json = {
            "identifier": cve.identifier,
            "assigner": cve.assigner,
            "description": cve.description,
            "severity": cve.severity,
            "cpe_match": cve.cpe_match
        }
        cve_json_collection.append(cve_json)
    json_object = json.dumps(cve_json_collection, indent=4)
    with open("cve_collections_for_all_programs.json", "w") as outfile:
        outfile.write(json_object)


def sccaner():
    cve_ = Cve_Of_Regisrty()
    list_cpe23_in_comp = cve_.get_cpe23name_of_programs()
    list_of_all_cve = cve_.scan_cve(list_cpe23_in_comp)
    return list_of_all_cve

