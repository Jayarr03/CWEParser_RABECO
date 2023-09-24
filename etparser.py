import xml.etree.ElementTree as ET

import parserUtils


def main():
    parser = parserUtils.ElementTreeParser()
    parser.parseCWE()


if __name__ == "__main__":
    main()
