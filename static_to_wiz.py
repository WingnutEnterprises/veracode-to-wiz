
import logging
import json
import datetime
import os
import base64
import requests

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
logger.addHandler(ch)


#
#
#
def severity_num_to_name(finding):
	# if severity == 0, does not show in the the Veracode JSON file
	if 'severity' in finding:
		num = finding['severity']
	else:
		num = 0

	match num:
		case 5:
			return 'Critical'
		case 4:
			return 'High'
		case 3:
			return 'Medium'
		case 2:
			return 'Low' 
		case _:
			return 'None'
#
#
#
def read_veracode_results():
	logging.info('reading results.json')

	try:
		with open('results.json', 'r') as file:
			data = json.load(file)
	except IOError as e:
		logging.error(f'Error {e} opening results.json')
		raise SystemExit

	return data


#
#
#
def convert_to_wiz(veracode_results):
	logging.info('Converting Veracode results to Wiz format')

	# header info
	wiz_data = {
		'integrationId': '12345',
		'dataSources': [
			{
				'id': 'repo_name',
				'analysisDate': datetime.datetime.now().replace(microsecond=0).isoformat(),
				'assets': [
					{
						'assetIdentifier': {
							'cloudProvider': 'GitHub',
							'providerId': 'wiz-repo-id'
						},
						'webAppVulnerabilityFindings': []
					}
				]
			}
		]
	}

	# loop through the flaws
	for finding in veracode_results['findings']:
		f = {
			'sastFinding': {
				'commitHash': '123',
				'filename': finding['files']['source_file']['file'],
				'lineNumbers': finding['files']['source_file']['line']
			},
			'id': finding['issue_id'],
			'name': finding['cwe_id'],
			'detailedName': finding['issue_type'],
			'severity': severity_num_to_name(finding),
			'externalFindingLink': '',
			'source': 'Veracode',
			'remediation': '',
			'description': finding['display_text']
		}

		wiz_data['dataSources'][0]['assets'][0]['webAppVulnerabilityFindings'].append(f)

	return wiz_data

#
#
#
def store_wiz_file(wiz_data):
	try:
		with open('wiz_results.json', 'w+') as file:
			file.write(json.dumps(wiz_data))
	except IOError as e:
		logging.error(f'Error {e} writing wiz_results.json')
		raise SystemExit

#
#
#
def upload_to_wiz():
	# get API Token
	endpoint = 'https://auth.app.wiz.io/oauth/token'
	#creds = os.getenv("WIZ_USER") + ':' + os.getenv('WIZ_PASSWORD')
	#b64_creds = base64.b64encode(creds.encode('utf-8'))
	headers = {'accept: application./json', 'content-type: application/x-www-form-urlencoded'}
	data = {'grant_type=client_credentials', 
		 'audience=wiz-api', 
		 f'client_id={os.getenv('WIZ_USER')}',
		 f'client_secret={os.getenv('WIZ_SECRET')}'}

	try:
		req = requests.post(endpoint, headers=headers, data=data, verify=False)         # verify=False for SSL cert error
		req.raise_for_status()
	except requests.exceptions.HTTPError as e:
		logger.error("Error getting API token, exiting.")
		raise SystemExit(e)
	
	info = req.json()
	token = info['token']
	logger.debug("Got API token")
	# request an upload slot

	# upload the file

	pass


#
#
#
if __name__ == '__main__':
	# read results.json (for demo purposes, assume it already exists in the root of the repo)
	veracode_results = read_veracode_results()

	# convert Veracode JSON to Wiz JSON
	wiz_results = convert_to_wiz(veracode_results)

	# write the new json (temp folder)
	wiz_file = store_wiz_file(wiz_results)

	# upload file to Wiz
	upload_to_wiz(wiz_file)

	logger.info('Done')
