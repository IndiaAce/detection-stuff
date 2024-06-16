import tomllib
import os

list = {}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)
                
                # Retrieve metadata
                date = alert.get('metadata', {}).get('creation_date', 'unknown_date')
                
                # Retrieve rule information with default values
                rule = alert.get('rule', {})
                name = rule.get('name', 'unknown_name')
                author = rule.get('author', 'unknown_author')
                risk_score = rule.get('risk_score', 'unknown_risk_score')
                severity = rule.get('severity', 'unknown_severity')
                filtered_object_array = []

                # Check for 'threat' key and its structure
                if 'threat' in rule and rule['threat'][0].get('framework') == "MITRE ATT&CK":
                    for threat in rule['threat']:
                        technique_info = threat.get('technique', [{}])[0]
                        technique_id = technique_info.get('id', 'unknown_id')
                        technique_name = technique_info.get('name', 'unknown_name')

                        tactic = threat.get('tactic', {}).get('name', 'none')

                        subtechnique_info = technique_info.get('subtechnique', [{}])[0]
                        subtechnique_id = subtechnique_info.get('id', 'none')
                        subtechnique_name = subtechnique_info.get('name', 'none')

                        technique = technique_id + " - " + technique_name
                        subtech = subtechnique_id + " - " + subtechnique_name

                        obj = {'tactic': tactic, 'technique': technique, 'subtech': subtech}
                        filtered_object_array.append(obj)

                obj = {'name': name, 'date': date, 'author': author, 'risk_score': risk_score, 'severity': severity, 'mitre': filtered_object_array}
                list[file] = obj

output_path = "metrics/detectiondata.csv"

with open(output_path, "w") as outF:
    outF.write("name,date,author,risk_score,severity,tactic,technique,subtechnique\n")

    separator = "; "
    for line in list.values():
        date = line['date']
        name = line['name']
        author = str(line['author']).replace(",", ";")
        risk_score = str(line['risk_score'])
        severity = line['severity']

        tactic = []
        tech = []
        subtech = []

        for technique in line['mitre']:
            tactic.append(technique['tactic'])
            tech.append(technique['technique'])
            subtech.append(technique['subtech'])
        outF.write(name + "," + date + "," + author + "," + risk_score + "," + severity + "," + separator.join(tactic) + "," + separator.join(tech) + "," + separator.join(subtech) + "\n")
