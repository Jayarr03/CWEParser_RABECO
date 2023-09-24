import parserUtils


def main():
    loader = parserUtils.CWEDownload()
    loader.loadAndUnzip()
    textparser = parserUtils.TextParser()
    textparser.parseCWE()
    textparser.removeTmpFiles()


if __name__ == "__main__":
    main()
