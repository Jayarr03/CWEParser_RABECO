import parserUtils


def main():
    # to remove the combined.json just delete the "True" in parseCWE()
    parser = parserUtils.ElementTreeParser()
    parser.parseCWE()


if __name__ == "__main__":
    main()
