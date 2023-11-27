"""
A file-based database, requires a writeable directory (path), which is usually
a requirement for drivers. It can store any additional metadata, accessible  as
a dictionary and serialized to and from JSON. This metadata file gets created
if it doesn't exist.
"""
from __future__ import annotations

import os

import orjson


def connection(path, serializer="raw"):
    serializers = {"raw": RawSerializer, "json": JSONSerializer}
    return FileBasedDatabase(path, serializer=serializers[serializer])


class FileBasedDatabase:
    def __init__(self, directory_path, serializer=None):
        self.directory_path = directory_path
        self.serializer = serializer or RawSerializer
        self.files = []

    def get(self, name):
        """
        Find the file from name, return the serializer instantiated with it. If
        the file path does not exist it will not return anything. Similar to
        how a `.get()` would work in a dictionary.
        """
        if not name.endswith(self.serializer.ext):
            name = f"{name}{self.serializer.ext}"
        if self.files == []:
            self._update_file_cache()
        if name in self.files:
            path = os.path.join(self.directory_path, name)
            return self.serializer(path)
        return None

    def create(self, name):
        """
        If `name` does not exist, go ahead and return a serializer with the
        path regardless, so that it can commit data to it. It does not check if
        the file exists or not, the serializer should be able to write to it.
        """
        if not name.endswith(self.serializer.ext):
            name = f"{name}{self.serializer.ext}"
        path = os.path.join(self.directory_path, name)
        return self.serializer(path)

    def get_all(self):
        """
        Retrieve all the files in the database directory path except for the
        metadata file which is special and not part of the saved data.
        """
        for name in self._update_file_cache():
            yield self.serializer(os.path.join(self.directory_path, name))

    def _update_file_cache(self):
        all_files = [i for i in os.listdir(self.directory_path) if ".__meta__.json" not in i]
        self.files = [i for i in all_files if i.endswith(self.serializer.ext)]
        return self.files

    def get_metadata(self):
        """
        This is a special method that loads (or creates) the metadata file in
        the directory. This metadata file allows to stick any information as
        a flat JSON file that can be loaded and saved as a regular file.

        If the file does not exist, it gets initialized with an empty JSON
        object so that callers don't get exceptions.
        """
        name = ".__meta__.json"
        path = os.path.join(self.directory_path, name)
        if not os.path.exists(path):
            with open(path, "w") as fp:
                fp.write("{}")
        meta = JSONSerializer(path)
        meta.load()
        return meta


class JSONSerializer:
    ext = ".json"

    def __init__(self, path):
        self.path = path
        self.data = {}

    def load(self):
        with open(self.path) as fp:
            self.data = orjson.loads(fp.read())
        return self.data

    def commit(self, data=None):
        """
        `data` is expected as a Python dictionary, this method takes care of
        serializing back to JSON before saving
        """
        # allow to commit what exists already as self.data if data is not passed in
        data = data or self.data
        self.data.update(data)
        with open(self.path, "wb") as fp:
            fp.write(orjson.dumps(data))


class RawSerializer:
    ext = ".txt"

    def __init__(self, path):
        self.path = path
        self.data = None

    def load(self):
        with open(self.path) as fp:
            self.data = fp.read()
        return self.data

    def commit(self, data):
        with open(self.path, "w") as fp:
            fp.write(data)
