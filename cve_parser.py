import download_db
import json
from cve import Cve
from dataclasses import dataclass
import os


@dataclass()
class CveParser:
    cve_collections_for_all_years = {}

    def __init__(self):
        self.cve_collections_for_all_years = download_db.DownloadDb().cve_dict

    def get_cve_collection_for_specific_year(self, year: str) -> []:
        """

        :param year:
        :return: list of all cve for the given year. Each cell in the returning list is cve object
        """
        # if not os.path.isfile('cve_collections_for_%s.json' % (str(year))):
        #     self.write_all_cve_collection_for_specific_year_to_file(year)
        cve_collection = []
        cve_dict = self.cve_collections_for_all_years[year]
        for cve_json_presentation in cve_dict['CVE_Items']:
            cve_id = cve_json_presentation['cve']['CVE_data_meta']['ID']
            assigner = None
            if 'ASSIGNER' in cve_json_presentation['cve']['CVE_data_meta'].keys():
                assigner = cve_json_presentation['cve']['CVE_data_meta']['ASSIGNER']
            description = cve_json_presentation['cve']['description']['description_data'][0]['value']
            severity = None
            cpe_match = []
            for node in cve_json_presentation['configurations']['nodes']:
                cpe_match += node['cpe_match']
            if len(cve_json_presentation['impact']) > 1:
                severity = self.extract_severity(cve_json_presentation['impact'])
            cve = Cve(cve_id, assigner, description, severity, cpe_match)
            cve_collection.append(cve)

        return cve_collection

    def write_all_cve_collection_for_specific_year_to_file(self, year: str):
        """

        :param year:
        :return: This function write all the cve objects of a given year to Json file named : "cve_collections_for_{0}.json"
        """
        cve_collection = self.get_cve_collection_for_specific_year(year)
        cve_json_collection = []
        for cve in cve_collection:
            cve_json = {
                "identifier": cve.identifier,
                "assigner": cve.assigner,
                "description": cve.description,
                "severity": cve.severity,
                "cpe_match": cve.cpe_match
            }
            cve_json_collection.append(cve_json)
        json_object = json.dumps(cve_json_collection, indent=4)
        with open("cve_collections_for_{0}.json".format(year), "w") as outfile:
            outfile.write(json_object)

    @staticmethod
    def extract_severity(impact: []) -> str:
        if len(impact) > 1:
            severity = impact['baseMetricV3']['cvssV3']['baseSeverity']
        else:
            severity = impact['baseMetricV2']['severity']

        return severity