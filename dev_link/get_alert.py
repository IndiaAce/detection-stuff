import requests as rq
import os


api_key = os.environ['ELASTIC_KEY']
url = "https://331ca4dd4436440885f15b4548242044.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules?rule_id="
id = "6aace640-e631-4870-ba8e-5fdda09325db"
full_path = url + id

headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}
elastic_data = rq.get(full_path, headers=headers).json()
print(elastic_data)