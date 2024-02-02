import json
import pandas as pd

# Specify the JSON file path
json_file_path = r"\file_path"

# Open the JSON file and read its content
with open(json_file_path, 'r', encoding='utf-8') as file:
    json_data = json.load(file)

# Extract 'id', 'name', and 'description' from each object under "CWE"
data_list = []

if "CWE" in json_data:
    for item in json_data["CWE"]:
        if isinstance(item, dict):
            data_list.append({
                'id': item.get('id'),
                'name': item.get('name'),
                'description': item.get('description')
            })

# Convert to DataFrame
df = pd.DataFrame(data_list)

# Specify the Excel file path
excel_file_path = 'output.xlsx'

# Write DataFrame to Excel
df.to_excel(excel_file_path, index=False)

print(f"Data from {json_file_path} has been successfully parsed and saved to {excel_file_path}")
