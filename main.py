import parserUtils


def main():
    loader = parserUtils.CWEDownload()
    loader.loadAndUnzip()
    textparser = parserUtils.TextParser()
    textparser.replaceDescription()
    textparser.extractCWE()
    textparser.cweToJson()

if __name__ == "__main__":
    main()
