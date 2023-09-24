import xml.etree.ElementTree as ET


def main():
    tree = ET.parse("testing\\cwec_v4.12.xml")
    root = tree.getroot()
    weaknesses = root.find("{http://cwe.mitre.org/cwe-7}Weaknesses")
    for weakness in weaknesses:
        print(weakness.attrib)
        for des in weakness:
            if "{http://cwe.mitre.org/cwe-7}Description" == des.tag:
                print(des.text)





if __name__ == "__main__":
    main()