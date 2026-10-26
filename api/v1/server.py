from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import os, json

app = Flask(__name__)
CORS(app)
db = {}

def initdb():
	global db
	print("[INFO] - Initializing database...")
	with open('../../DB/db.json', 'r') as dbfile:
		db = json.load(dbfile)
	print("[INFO] - Finished initializing database!")

@app.after_request
def after_request(response):
	response.headers.add('Access-Control-Allow-Origin', '*')
	response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,cve,poc-id')
	response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
	return response

@app.route('/utils/test', methods=['POST'])
def testapi():
	return "Pong!"

@app.route('/poc/code', methods=['GET'])
def poccode():
	if 'poc-id' in request.headers:
		id = request.headers.get("poc-id")
		try:
			if db[f"{str(id)}"]:
				code_path = db[f"{id}"]["code_path"]
				if code_path:
					if os.path.exists(code_path):
						with open(code_path, 'r') as codefile:
							code = codefile.read()
							codefile.close
						return code
					else:
						return "Path does not exist!"
		except KeyError:
			return "Could not find poc in the database."
	else:
		return "Please specify the poc-id in headers."

@app.route('/poc/data', methods=['GET'])
def pocdata():
	if 'poc-id' in request.headers:
		id = request.headers.get("poc-id")
		try:
			if db[f"{str(id)}"]:
				poc = db[f"{id}"]
				try:
					return jsonify({"cve": poc["CVE"], "type": poc["type"], "isremote": poc["isRemote"], "cvss": poc["CVSS"], "desc": poc["desc"], "path": str(poc["code_path"]).replace("../..", ""), "dlpath": str(poc["zip_path"]).replace(".txt", ".zip")})
				except Exception as e:
					print("[ERROR] - Could not retreive data for PoC id: {0}\nerror: {1}".format(str(id), e))
					return e
		except KeyError:
			return "Could not find poc in the database."
	else:
		return "Please specify the poc-id in headers."

@app.route('/utils/cve2id', methods=['GET'])
def cve2id():
	if 'cve' in request.headers:
		id = request.headers.get("cve")
		try:
			#if db[f"{str(id)}"]:
				#poc = db[f"{id}"]
				try:
					while True:
						count = 1
						if db[f"{count}"]:
							if db[f"{str(count)}"]["CVE"] == id:
								return f"{str(count)}"
							else:
								count += 1
						else:
							return "None found!"
				except KeyError:
					print("KeyError.")
					return "KeyError!"
		except KeyError:
			#print("")
			return "CVE not found."
	else:
		return "Please specify the CVE."

if __name__ == "__main__":
	initdb()
	print(f"DB: {db}")
	app.run(debug=False)
