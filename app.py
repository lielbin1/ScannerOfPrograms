from flask import Flask, request, jsonify, render_template

from cpe_to_cve import sccaner, write_cve_of_programs_to_json
from json_to_html import Json_To_HTML


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
