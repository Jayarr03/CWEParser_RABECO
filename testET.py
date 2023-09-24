import xml.etree.ElementTree as ET

import parserUtils


def main():
    parser = parserUtils.ElementTreeParser()
    parser.parseCWE()
    # tree = ET.parse("testing\\cwec_v4.12.xml")
    # cwe = open("cwe.json", "w")
    # cwe.write("{\"CWE\":[")
    # root = tree.getroot()
    # weaknesses = root.find("{http://cwe.mitre.org/cwe-7}Weaknesses")
    # for weakness in weaknesses:
    #     id_name = "{{\"id\":\"{}\", \"name\": \"{}\", ".format(weakness.attrib["ID"], weakness.attrib["Name"].replace("\\", "\\\\"))
    #     for des in weakness:
    #         if "{http://cwe.mitre.org/cwe-7}Description" == des.tag:
    #             tmp_des = des.text
    #             tmp_des = tmp_des.replace("\\", "\\\\").replace("\"", "\\\"")
    #             id_name_des = id_name + "\"description\":\"{}\"}},".format(tmp_des).\
    #                 replace("\n", " ").\
    #                 replace(u"\u0009", " ") + "\n"
    #             cwe.write(id_name_des)
    # cwe.write("{}]}")


if __name__ == "__main__":
    main()
