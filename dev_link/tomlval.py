import tomllib as tl
import sys
import os

failure = 0

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tl.load(toml)
                present_fields = []
                missing_fields = []

                try:
                    if not alert['metadata']['creation_date']:
                        pass
                except:
                    print("The metadata table does not contain a creation date on: " + full_path)
                    failure = 1
                if alert['rule']['type'] == "query":
                    required_fields = ['description', 'name','rule_id', 'risk_score', 'severity', 'type', 'query']
                elif alert['rule']['type'] == "eql":
                    required_fields = ['description', 'name','rule_id', 'risk_score', 'severity', 'type', 'query', 'language']
                elif alert['rule']['type'] == "threshold":
                    required_fields = ['description', 'name','rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break

                ############################# elif for future rule types. ############################
                '''elif alert['rule']['type'] == "eql":
                    required_fields = ['description', 'name', 'risk_score', 'severity', 'type', 'query', 'language']'''

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)

                if missing_fields:
                    print("There is a missing required field in " + file + ": " + str(missing_fields))
                    failure = 1
                else:
                    print("Validation pass for: " + file)
if failure != 0:
    sys.exit(1)