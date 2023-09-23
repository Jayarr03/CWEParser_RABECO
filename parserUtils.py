from urllib.request import urlretrieve
import zipfile


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
                    clean.write(line.strip())
                    clean.write("\"")

                if "<Description>" in line:
                    line = line.replace("<Description>", ", \"description\":\"")
                    line = line.replace("</Description>", "")
                    clean.write(line.replace("\n", ""))
                    clean.write("\"},")
                clean.write("\n")
        clean.write("]}")
        clean.close()


class CWEDownload:
    def __init__(self, filename="cwe_list.zip", link="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"):
        self.link = link
        self.filename = filename

    def downloadCWEList(self):
        """
        Downloads latest cwe list from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
        :return: None
        """
        url = self.link
        urlretrieve(url, filename=self.filename)

    def unzipCWEList(self):
        """
        Unzips downloaded .zip file
        :return: None
        """
        with zipfile.ZipFile(self.filename, "r") as zip:
            zip.extractall()

    def loadAndUnzip(self):
        self.downloadCWEList()
        self.unzipCWEList()
