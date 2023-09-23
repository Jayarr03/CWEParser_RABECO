from textParsedElements import parserUtils

def main():
    textparser = parserUtils.TextParser()
    textparser.replaceDescription()
    textparser.extractCWE()
    textparser.cweToJson()

if __name__ == "__main__":
    main()
