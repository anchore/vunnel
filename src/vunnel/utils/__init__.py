from dataclasses import fields


def dataclass_from_dict(cls, d):
    try:
        fieldtypes = {f.name: f.type for f in fields(cls)}
        return cls(**{f: dataclass_from_dict(fieldtypes[f], d[f]) for f in d})
    except TypeError:
        pass
    return d
