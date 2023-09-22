

def replaceDescription(filename: str):
    tmp = open("tmp.xml", "w")
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.replace("</Description>", "\n</Description>")
            tmp.write(line)

def extractCwe(filename: str):
    tmp = open(filename, "r")
    with open("cwe.txt", "w") as f:
        lines = tmp.readlines()
        for i in range(len(lines)):
            j = 1
            if "<Weakness ID=" in lines[i]:
                f.write(lines[i].replace("<Weakness", "\n<Weakness"))
                nextline = lines[i+j]
                while "</Description>" not in nextline:
                    f.write(nextline.replace("\n", ""))
                    j += 1
                    nextline = lines[i+j]
            continue



def main():
    replaceDescription("cwec_v4.12.xml")
    extractCwe("tmp.xml")
    clean = open("cwe.json", "w")
    clean.write("{ \"CWEs\": [")
    with open("cwe.txt", "r") as f:
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

if __name__ == "__main__":
    main()
