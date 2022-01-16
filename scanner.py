import os
import pathlib
from os import listdir

import get_files_programfiles
from cpe_to_cve import sccaner, write_cve_of_programs_to_json
from cve_parser import CveParser
from installed_softwares import InstalledSoftware
from searchEngine import SearchEngineBuilder, CpeSwFitter
from xmlParser import CpeXmlParser
import download_db
import sys


# from download_all_zips_files import DownloadDb

def scanner():
    print("Please wait, the download will take a few minutes...", file=sys.stdout)
    download_db.DownloadDb()
    print("Done", file=sys.stdout)
    print("All the folders of the Sequence by years have been downloaded and exist in a folder named nvd",
          file=sys.stdout)
    # print(download_db.DownloadDb().cve_dict)
    if not os.path.isfile('official-cpe-dictionary_v2.3.xml', file=sys.stdout):
        print("Download all cpe from web.....", file=sys.stdout)
        download_db.download_cpe_file()
        download_db.unzip_file('official-cpe-dictionary_v2.3.xml.zip', directory_to_extract=None, file=sys.stdout)
        print("Done", file=sys.stdout)

    if not os.path.isfile("registry_data.json", file=sys.stdout):
        print("Download all programs in the computer.....", file=sys.stdout)
        i_s = InstalledSoftware()
        i_s.dump_software_lst_to_json(["Publisher", 'DisplayVersion', 'DisplayName'])
        print("Done", file=sys.stdout)

    if not os.path.isfile("parsed_xml.csv"):
        print("Scan the appropriate CPE for the software on your computer.....", file=sys.stdout)
        a = CpeXmlParser('official-cpe-dictionary_v2.3.xml')
        a.csv_creator('official-cpe-dictionary_v2.3.xml')

    if not os.path.isfile("retrieved_cosin.csv"):
        sim_func_names_list = ["cosin"]
        for func in sim_func_names_list:
            search_builder = SearchEngineBuilder()
            search_builder.create_models("parsed_xml.csv", func)
            cpe_sw_fitter = CpeSwFitter("parsed_xml.csv", func)
            cpe_sw_fitter.fit_all(1)
        print("Done", file=sys.stdout)
    list_of_all_cve = sccaner()
    write_cve_of_programs_to_json(list_of_all_cve)

    print("Done", file=sys.stdout)
    print(
        "The Jason file name -cve_collections_for_all_programs- is ready, now you can see the vulnerabilities for the software on your computer",
        file=sys.stdout)
    print("end", file=sys.stdout)
