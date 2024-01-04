import sys
import xml.etree.ElementTree as ET
import json

def parse_nessus(xml_file, output_file):
    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Data extraction and transformation
    combined_data = {}

    for report in root.findall('Report'):
        for report_host in report.findall('ReportHost'):
            ip_address = report_host.get('name')

            for report_item in report_host.findall('ReportItem'):
                title = report_item.get('pluginName', '')
                affected_component = ip_address + ':' + \
                                     report_item.get('port', '') + ':' + \
                                     report_item.get('protocol', '')

                cvss3_vector = report_item.find('cvss3_vector')
                if cvss3_vector is None or not cvss3_vector.text:
                    continue  # Skip entries without cvss3_vector

                cvss3_vector = cvss3_vector.text

                # Extracting other details
                summary = report_item.find('synopsis')
                summary = summary.text if summary is not None else ''

                description = report_item.find('description')
                description = description.text if description is not None else ''

                recommendation = report_item.find('solution')
                recommendation = recommendation.text if recommendation is not None else ''

                # Handle bullet points and new lines with a space
                description = description.replace('\n', ' ').replace('- ', '\n* ')
                recommendation = recommendation.replace('\n', ' ').replace('- ', '\n* ')

                # Combining data with the same title
                if title in combined_data:
                    combined_data[title]["data"]["affected_components"].append(affected_component)
                else:
                    combined_data[title] = {
                        "status": "in-progress",
                        "data": {
                            "cvss": cvss3_vector,
                            "title": title,
                            "summary": summary,
                            "references": [],  # Assuming references need to be added manually
                            "description": description,
                            "recommendation": recommendation,
                            "affected_components": [affected_component]
                        }
                    }

    # Remove duplicate affected components and convert to list format
    for title, item in combined_data.items():
        item["data"]["affected_components"] = list(set(item["data"]["affected_components"]))

    # Convert dictionary to list format for JSON
    final_data = list(combined_data.values())

    # Write to JSON file
    with open(output_file, 'w') as file:
        json.dump(final_data, file, indent=4)

if __name__ == "__main__":
    # Check if arguments are given
    if len(sys.argv) != 3:
        print("Usage: python nessus-to-json.py [input_file.nessus] [output_file.json]")
        sys.exit(1)

    # Extract file paths from arguments
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Run the conversion process
    parse_nessus(input_file, output_file)
    print(f"Conversion completed. Output file: {output_file}")
