import xml.etree.ElementTree as ET


def main():
    tree = ET.parse("cwec_v4.12.xml")
    root = tree.getroot()
    weaknesses = root.find("{http://cwe.mitre.org/cwe-7}Weaknesses")
    for weakness in weaknesses:
        for elem in weakness.iter():
            print(elem.tag)

if __name__ == "__main__":
    main()