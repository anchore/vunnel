from __future__ import annotations

import pytest
from vunnel.utils import fdb as db


class TestGetJSON:
    @pytest.mark.parametrize("name", ["doesnotexist", "doesnotexist.json"])
    def test_does_not_find_file_name(self, name, tmpdir):
        conn = db.connection(tmpdir.strpath, serializer="json")
        assert conn.get(name) is None

    @pytest.mark.parametrize("name", ["exists", "exists.json"])
    def test_finds_file_name(self, name, tmpdir):
        _file = tmpdir.join("exists.json")
        _file.write("{}")
        conn = db.connection(tmpdir.strpath, serializer="json")
        record = conn.get(name)
        record.load()
        assert record.data == {}

    def test_ignores_other_ext(self, tmpdir):
        _file = tmpdir.join("exists.vim")
        _file.write("{}")
        conn = db.connection(tmpdir.strpath, serializer="json")
        record = conn.get("exists")
        assert record is None

    @pytest.mark.parametrize("name", ["new", "new.json"])
    def test_creates_data(self, name, tmpdir):
        conn = db.connection(tmpdir.strpath, serializer="json")
        record = conn.create(name)
        record.commit({"a": 1})
        record = conn.get(name)
        record.load()
        assert record.data == {"a": 1}

    def test_gets_all_files(self, tmpdir):
        conn = db.connection(tmpdir.strpath, serializer="json")
        for i in range(9):
            record = conn.create(str(i))
            record.commit({"name": str(i)})
        records = conn.get_all()
        assert len(list(records)) == 9


class TestMeta:
    def test_doesnt_get_mixed(self, tmpdir):
        conn = db.connection(tmpdir.strpath, serializer="json")
        for i in range(9):
            record = conn.create(str(i))
            record.commit({})
        meta = conn.get_metadata()
        meta.commit({"name": "metadata"})
        meta.commit({"type": "json"})
        reloaded_meta = conn.get_metadata()
        reloaded_meta.load()
        assert reloaded_meta.data == {"type": "json"}
        records = conn.get_all()
        assert len(list(records)) == 9

    def test_updates(self, tmpdir):
        conn = db.connection(tmpdir.strpath, serializer="json")
        meta = conn.get_metadata()
        meta.commit({"name": "metadata"})
        meta.data["type"] = "json"
        meta.commit()

        reloaded_meta = conn.get_metadata()
        reloaded_meta.load()
        assert reloaded_meta.data["type"] == "json"
        assert reloaded_meta.data["name"] == "metadata"


class TestGetRaw:
    @pytest.mark.parametrize("name", ["doesnotexist", "doesnotexist.txt"])
    def test_does_not_find_file_name(self, name, tmpdir):
        conn = db.connection(tmpdir.strpath, serializer="raw")
        assert conn.get(name) is None

    @pytest.mark.parametrize("name", ["exists", "exists.txt"])
    def test_finds_file_name(self, name, tmpdir):
        _file = tmpdir.join("exists.txt")
        _file.write("Some Text Here")
        conn = db.connection(tmpdir.strpath, serializer="raw")
        record = conn.get(name)
        record.load()
        assert record.data == "Some Text Here"

    @pytest.mark.parametrize("name", ["new", "new.txt"])
    def test_creates_data(self, name, tmpdir):
        conn = db.connection(tmpdir.strpath, serializer="raw")
        record = conn.create(name)
        record.commit("new text")
        record = conn.get(name)
        record.load()
        assert record.data == "new text"
