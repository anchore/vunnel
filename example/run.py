# ruff: noqa: INP001

import logging
from unittest import mock

import awesome
import orjson

from vunnel import provider, result

fakedata = [
    {
        "name": "FAKE-SA-001",
        "packages": ["curl"],
        "severity": "Critical",
        "description": "Bad thing, really bad thing",
        "affected": "1.0",
        "fixed": "2.0",
    },
    {
        "name": "FAKE-SA-002",
        "packages": ["wget"],
        "severity": "Low",
        "description": "Not really a bad thing, but no fix yet",
        "affected": "5.0",
        "fixed": None,
    },
]


def main():
    # we just want to show the parser working, but not against any real data. For that reason we'll mock
    # this like we would in a unit test.
    with mock.patch("awesome.parser.requests.get") as get:
        get.return_value = mock.Mock(
            json=lambda: fakedata,
            text=orjson.dumps(fakedata),
            raise_for_status=lambda: None,
            status_code=200,
        )

        config = awesome.Config(
            runtime=provider.RuntimeConfig(
                result_store=result.StoreStrategy.FLAT_FILE,
                existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
            ),
        )

        my_provider = awesome.Provider(root="./data", config=config)
        my_provider.run()


if __name__ == "__main__":

    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )

    main()
