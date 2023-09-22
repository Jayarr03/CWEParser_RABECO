class TextParser:
    def __init__(self, tmpfilename = "tmp.xml", cwe_file = "cwec_v4.12.xml"):
        self.cwe_file = cwe_file
        self.tmpFilename = tmpfilename

    def replaceDescription(self):
        tmp = open("tmp.xml", "w", encoding="utf-8")
        with open(self.cwe_file, "r", encoding="utf-8") as f:
            for line in f.readlines():
                line = line.replace("</Description>", "\n</Description>")
                tmp.write(line)
        tmp.close()

    def extractCWE(self):
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

    def cleanCWEOut(self):
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
