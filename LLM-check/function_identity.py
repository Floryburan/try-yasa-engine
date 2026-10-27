"""Persistent source-definition identities, independent of runtime symbols."""

import posixpath


def definition_identity(row):
    fields = (posixpath.normpath(row["file"].replace("\\", "/")), row.get("qualified_name", row["name"]),
              row.get("start_line"), row.get("start_column"), row.get("end_line"), row.get("end_column"),
              row.get("origin", "source_definition"))
    return fields


def deduplicate_definitions(rows):
    unique, groups = [], {}
    for row in rows:
        key = definition_identity(row)
        if key not in groups:
            item = dict(row, definition_identity=list(key), definition_alias_ids=[row["id"]])
            groups[key] = item
            unique.append(item)
        else:
            item = groups[key]
            if item.get("source", "").rstrip() != row.get("source", "").rstrip():
                raise ValueError("Conflicting source for the same function definition: " + row["file"])
            if row["id"] not in item["definition_alias_ids"]:
                item["definition_alias_ids"].append(row["id"])
    return unique
