from flask import Flask, request, jsonify, render_template
import os
import download_db
import main
from cpe_to_cve import sccaner, write_cve_of_programs_to_json
from installed_softwares import InstalledSoftware
from json_to_html import Json_To_HTML
from searchEngine import SearchEngineBuilder, CpeSwFitter
from xmlParser import CpeXmlParser


class MyFlaskApp(Flask):
    def run(self, host=None, port=None, debug=None, **options):
        super(MyFlaskApp, self).run(host=host, port=port, debug=debug, **options)


app = MyFlaskApp(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False


@app.route("/", methods=['GET', 'POST'])
def index():
    ip_address = request.args.get("scanner")
    return render_template("index.html")

@app.route("/scanner", methods=['GET', 'POST'])
def scanner():
    Json_To_HTML()
    download_db.DownloadDb()
    # print(download_db.DownloadDb().cve_dict)
    if not os.path.isfile('official-cpe-dictionary_v2.3.xml'):
        download_db.download_cpe_file()
        download_db.unzip_file('official-cpe-dictionary_v2.3.xml.zip', directory_to_extract=None)

    if not os.path.isfile("registry_data.json"):
        i_s = InstalledSoftware()
        i_s.dump_software_lst_to_json(["Publisher", 'DisplayVersion', 'DisplayName'])

    if not os.path.isfile("parsed_xml.csv"):
        a = CpeXmlParser('official-cpe-dictionary_v2.3.xml')
        a.csv_creator('official-cpe-dictionary_v2.3.xml')

    if not os.path.isfile("retrieved_cosin.csv"):
        sim_func_names_list = ["cosin"]
        for func in sim_func_names_list:
            search_builder = SearchEngineBuilder()
            search_builder.create_models("parsed_xml.csv", func)
            cpe_sw_fitter = CpeSwFitter("parsed_xml.csv", func)
            cpe_sw_fitter.fit_all(1)
        print("end")
    list_of_all_cve = sccaner()
    write_cve_of_programs_to_json(list_of_all_cve)
    return render_template("scanner.html")
#

# @app.route('/')
# def hello_world():
#     ip_addr = request.remote_addr
#     return '<h1> Your IP address is:' + ip_addr
#

if __name__ == '__main__':
    # run the Flask RESTful API, make the server publicly available (host='0.0.0.0') on port 8080
    app.run(host='0.0.0.0', port=5000, debug=True)
