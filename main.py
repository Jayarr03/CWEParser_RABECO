import parserUtils


def main():
    loader = parserUtils.CWEDownload()
    loader.loadAndUnzip()
    textparser = parserUtils.TextParser()
    textparser.parseCWE()

if __name__ == "__main__":
    main()
