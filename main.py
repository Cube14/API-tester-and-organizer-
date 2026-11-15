from src.parser.openapi_parser import OpenAPIParser


def main():
    parser = OpenAPIParser("config/sample_api.yaml")
    parser.display_endpoints()


if __name__ == "__main__":
    main()