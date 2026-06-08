from __future__ import annotations


def itanium_name(suffix: str) -> str | None:
    """Decode an Itanium ABI class name from the post-_ZTV/_ZTI suffix.

    Handles two forms:
      N<len><part>...<len><part>E  — nested name (e.g. N3Foo3BarE → Foo::Bar)
      <len><name>                  — simple name  (e.g. 6Logger  → Logger)
    """
    if not suffix:
        return None
    if suffix[0] == "N":
        parts: list[str] = []
        i = 1
        while i < len(suffix) and suffix[i] != "E":
            if not suffix[i].isdigit():
                i += 1
                continue
            j = i
            while j < len(suffix) and suffix[j].isdigit():
                j += 1
            try:
                n = int(suffix[i:j])
            except ValueError:
                break
            if j + n > len(suffix):
                break
            parts.append(suffix[j : j + n])
            i = j + n
        return "::".join(parts) if parts else None
    if suffix[0].isdigit():
        i = 0
        while i < len(suffix) and suffix[i].isdigit():
            i += 1
        try:
            n = int(suffix[:i])
            return suffix[i : i + n] if i + n <= len(suffix) else None
        except ValueError:
            return None
    return None
