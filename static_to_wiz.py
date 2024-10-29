
import logging
import json
import datetime

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
logger.addHandler(ch)


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

	foo = json.dumps(wiz_data)
	return json.dumps(wiz_data)

#
#
#
def store_wiz_file():
	pass

#
#
#
def upload_to_wiz():
	pass


#
#
#
if __name__ == '__main__':
	# read results.json (for demo purposes, assume it already exists in the root of the repo)
	veracode_results = read_veracode_results()

	# convert Veracode JSON to Wiz JSON
	convert_to_wiz(veracode_results)

	# write the new json (temp folder)
	store_wiz_file()

	# upload file to Wiz
	upload_to_wiz()
