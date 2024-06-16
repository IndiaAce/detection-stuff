import requests as rq
import os
import tomllib as tl


api_key = os.environ['ELASTIC_KEY']
url = "https://331ca4dd4436440885f15b4548242044.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

changed_files = os.environ["CHANGED_FILES"]

data = ""

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file in changed_files:
            data = "{\n"
            if file.endswith(".toml"):
                full_path = os.path.join(root, file)
                with open(full_path,"rb") as toml:
                    alert = tl.load(toml)
                    if alert['rule']['type'] == "query":
                        required_fields = ['author','description', 'name','rule_id', 'risk_score', 'severity', 'type', 'query','threat']
                    elif alert['rule']['type'] == "eql":
                        required_fields = ['author','description', 'name','rule_id', 'risk_score', 'severity', 'type', 'query', 'language','threat']
                    elif alert['rule']['type'] == "threshold":
                        required_fields = ['author','description', 'name','rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold','threat']
                    else:
                        print("Unsupported rule type found in: " + full_path)
                        break
                    for field in alert['rule']:
                        if field in required_fields:
                            if type(alert['rule'][field])==list:
                                data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                            elif type(alert['rule'][field])==str:
                                if field == 'description':
                                    data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n", " ").replace("\"", "\\\"").replace("\\","\\\\") + "\"," + "\n"
                                elif field == 'query':
                                    data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n"," ") + "\"," + "\n"
                                else:       
                                    data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n", " ").replace("\"", "\\\"") + "\"," + "\n"
                            elif type(alert['rule'][field])==int:
                                data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                            elif type(alert['rule'][field])==dict:
                                data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                data += "  \"enabled\": true\n}"
        #print(data) #used for troubleshooting  

            rule_id=(alert['rule']['rule_id'])
            url = url + "?rule_id=" + rule_id
            elastic_data = rq.put(url, headers=headers, data=data).json()
            print(elastic_data)