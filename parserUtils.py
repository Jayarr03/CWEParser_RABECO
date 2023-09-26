import os
from urllib.request import urlretrieve
import zipfile
import xml.etree.ElementTree as ET


class TextParser:
    def __init__(self, cwe_file="cwec_v4.12.xml"):
        self.cwe_file = cwe_file

    def replaceDescription(self):
        """
        Places a newline before every Description-tag to simplify parsing
        :return: No return value. Generates a new file called tmp.xml with the newly placed tags
        """
        tmp = open("tmp.xml", "w", encoding="utf-8")
        with open(self.cwe_file, "r", encoding="utf-8") as f:
            for line in f.readlines():
                line = line.replace("</Description>", "\n</Description>")
                tmp.write(line)
        tmp.close()

    def extractCWE(self):
        """
        Extracts every Weakness with given description and prints them to a txt-file
        :return: No return, only cwe.txt is created
        """
        tmp = open("tmp.xml", "r", encoding="utf-8")
        with open("cwe.txt", "w", encoding="utf-8") as f:
            lines = tmp.readlines()
            for i in range(len(lines)):
                j = 1
                if "<Weakness ID=" in lines[i]:
                    f.write(lines[i].replace("<Weakness", "\n<Weakness"))
                    nextline = lines[i + j]
                    while "</Description>" not in nextline:
                        f.write(nextline.replace("\n", ""))
                        j += 1
                        nextline = lines[i + j]
                continue
        tmp.close()

    def cweToJson(self):
        """
        Creates json-file by replacing tags with json-descriptors
        :return: Only cwe.json is created
        """
        clean = open("cwe.json", "w", encoding="utf-8")
        clean.write("{ \"CWEs\": [")
        with open("cwe.txt", "r", encoding="utf-8") as f:
            for line in f.readlines():
                line = line.replace("\"", "")
                if "Weakness ID" in line:
                    clean.write("{")
                    line = line.replace("<Weakness ID=", "\"id\":\"")
                    line = line.replace("Name=", "\", \"name\":\"")
                    line = line.replace("Abstraction=", "\", \"abstraction\":\"")
                    line = line.replace("Structure=", "\", \"structure\":\"")
                    line = line.replace("Status=", "\", \"status\":\"")
                    line = line.replace("\n", "")
                    line = line.replace(">", "")
                    line = line.replace(u"\u0009", "")
                    line = line.replace("\\", "\\\\")
                    line = " ".join(line.split())
                    clean.write(line.strip())
                    clean.write("\"")

                if "<Description>" in line:
                    line = line.replace("<Description>", ", \"description\":\"")
                    line = line.replace("</Description>", "")
                    line = line.replace(u"\u0009", "")
                    line = line.replace("\\", "\\\\")
                    line = " ".join(line.split())
                    clean.write(line.replace("\n", ""))
                    clean.write("\"},")
                clean.write("\n")
        clean.write("{}")
        clean.write("]}")
        clean.close()

    def parseCWE(self):
        """
        Parses downloaded CWE list and creates a .json file
        :return:
        """
        self.replaceDescription()
        self.extractCWE()
        self.cweToJson()

    def removeTmpFiles(self):
        """
        Removes unnecessary files (.zip, .txt, .xml)
        :return: None
        """
        filelist = os.listdir()
        for item in filelist:
            if item.endswith(".zip") or item.endswith(".txt") or item.endswith(".xml"):
                os.remove(item)


class CWEDownload:
    def __init__(self, filename="cwe_list.zip", link="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"):
        self.link = link
        self.filename = filename

    def downloadCWEList(self):
        """
        Downloads latest cwe list from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
        :return: None
        """
        urlretrieve(self.link, filename=self.filename)

    def unzipCWEList(self):
        """
        Unzips downloaded .zip file
        :return: None
        """
        with zipfile.ZipFile(self.filename, "r") as zip:
            zip.extractall()

    def loadAndUnzip(self):
        """
        Downloads and unzips .zip archive of CWE list
        :return: None
        """
        self.downloadCWEList()
        self.unzipCWEList()


class ElementTreeParser:
    def __init__(self, cwe_file="cwec_v4.12.xml"):
        self.cwe_file = cwe_file

    def etParser(self):
        """
        Uses ElementTree to parse the cwe .xml file to a .json file. Takes the path as argument which should be given by the constructor
        :return: None. Produces a file called cwe.json
        """
        tree = ET.parse(self.cwe_file)
        cwe = open("cwe.json", "w")
        cwe.write("{\"CWE\":[\n")
        root = tree.getroot()
        weaknesses = root.find("{http://cwe.mitre.org/cwe-7}Weaknesses")
        for weakness in weaknesses:
            id_name = "{{\"id\":\"{}\", \"name\": \"{}\", ".format(weakness.attrib["ID"],
                                                                   weakness.attrib["Name"].replace("\\", "\\\\"))
            for des in weakness:
                if "{http://cwe.mitre.org/cwe-7}Description" == des.tag:
                    tmp_des = des.text
                    tmp_des = tmp_des.replace("\\", "\\\\").replace("\"", "\\\"")
                    id_name_des = id_name + "\"description\":\"{}\"}},".format(tmp_des). \
                        replace("\n", " "). \
                        replace(u"\u0009", " ") + "\n"
                    id_name_des = " ".join(id_name_des.split()) + "\n"
                    cwe.write(id_name_des)
        cwe.close()
        with open("cwe.json", "rb+") as f:
            f.seek(-4, 2)
            f.truncate()
            f.write(b"}\n]}")
        self.getCategories()

    def getCategories(self):
        """
        Creates another .json file with name, ids and summaries of all categories. It's automatically called during
        the parsing process
        :return: None
        """
        tree = ET.parse(self.cwe_file)
        cats = open("categories.json", "w")
        cats.write("{\"Categories\":[\n")
        root = tree.getroot()
        categories = root.find("{http://cwe.mitre.org/cwe-7}Categories")
        for category in categories:
            id_name = "{{\"id\":\"{}\", \"name\": \"{}\", ".format(category.attrib["ID"],
                                                                   category.attrib["Name"].replace("\\", "\\\\"))
            for cat in category:
                if "{http://cwe.mitre.org/cwe-7}Summary" == cat.tag:
                    tmp_des = cat.text
                    tmp_des = tmp_des.replace("\\", "\\\\").replace("\"", "\\\"")
                    id_name_des = id_name + "\"summary\":\"{}\"}},".format(tmp_des). \
                        replace("\n", " "). \
                        replace(u"\u0009", " ") + "\n"
                    id_name_des = " ".join(id_name_des.split()) + "\n"
                    cats.write(id_name_des)
        cats.close()
        with open("categories.json", "rb+") as f:
            f.seek(-4, 2)
            f.truncate()
            f.write(b"}\n]}")

    def combineJsonFiles(self):
        """
        Combines both .json files to one .json file
        :return: None. Creates a file called combined.json
        """
        with open("combined.json", "w") as com:
            with open("categories.json", "r") as cat:
                with open("cwe.json", "r") as cwe:
                    for line in cwe:
                        if "]}" in line:
                            line = "],\n"
                        com.write(line)
                    for line in cat:
                        if "\"Categories\"" in line:
                            line = "\"Categories\":[\n"
                        com.write(line)



    def downloadAndUnzip(self):
        """
        Loads .xml file from https://cwe.mitre.org/data/downloads.html and unzips it
        :return: None
        """
        loader = CWEDownload()
        loader.loadAndUnzip()

    def removeTmpFiles(self):
        """
        Removes unnecessary files (.zip, .txt, .xml)
        :return: None
        """
        filelist = os.listdir()
        for item in filelist:
            if item.endswith(".zip") or item.endswith(".txt") or item.endswith(".xml"):
                os.remove(item)

    def parseCWE(self, combine=False):
        """
        Starts the whole parsing process and deletes unnecessary data afterwards
        :return: None
        """
        self.downloadAndUnzip()
        self.etParser()
        if combine:
            self.combineJsonFiles()
        self.removeTmpFiles()
