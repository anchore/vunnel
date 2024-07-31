import os

import orjson

root_directory = "tests/unit/providers"


def pretty_print_json_file(file_path):
    try:
        with open(file_path, "rb") as file:
            existing = file.read()
            data = orjson.loads(existing)

        formatted = orjson.dumps(
            data,
            option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS | orjson.OPT_APPEND_NEWLINE)
        if formatted == existing:
            return

        with open(file_path, "wb") as file:
            file.write(formatted)
            print(f"Formatted: {file_path}")
    except (OSError, orjson.JSONDecodeError) as e:
        print(f"Error processing {file_path}: {e}")


def main():
    for dirpath, _, filenames in os.walk(root_directory):
        if "test-fixtures/snapshots" in dirpath:
            for filename in filenames:
                if filename.endswith(".json"):
                    file_path = os.path.join(dirpath, filename)
                    pretty_print_json_file(file_path)

    print("JSON formatting complete.")
