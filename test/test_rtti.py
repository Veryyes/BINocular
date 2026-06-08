# Tests for C++ RTTI and vtable extraction across all disassembler backends.
#
# Three scenarios, each compiled into its own binary by `make cpp_rtti`:
#
#   rtti_simple  — Logger: one class, no inheritance
#   rtti_inherit — Shape → Polygon → Rectangle → Square (3-level single inheritance)
#   rtti_diamond — Vehicle ←(virtual) Car, Vehicle ←(virtual) Boat, Car+Boat → Amphibious
#
# Each scenario section has three assertion helpers (one per binary) that are
# called from per-backend test functions so failures pinpoint both the scenario
# and the backend.

import pytest

from binocular import ClassInfo


# ---------------------------------------------------------------------------
# Shared assertion helpers
# ---------------------------------------------------------------------------


def _assert_vtable(cls: ClassInfo, min_entries: int = 1) -> None:
    assert cls.vtable_addr is not None and cls.vtable_addr > 0, (
        f"{cls.name}: expected non-zero vtable_addr"
    )
    assert len(cls.vtable) >= min_entries, (
        f"{cls.name}: expected at least {min_entries} vtable entries, got {len(cls.vtable)}"
    )
    slots = [e.slot for e in cls.vtable]
    assert slots == sorted(slots), f"{cls.name}: vtable slots are not in order: {slots}"


def _assert_simple_rtti(binary) -> None:
    """Logger: one class, virtual methods, no inheritance."""
    classes = binary.classes
    assert "Logger" in classes, f"expected 'Logger' in classes, got: {list(classes)}"

    logger = classes["Logger"]
    assert logger.base_classes == [], "Logger should have no base classes"
    assert logger.derived_classes == [], "Logger should have no derived classes"
    assert not logger.has_multiple_inheritance
    assert not logger.has_virtual_inheritance

    # Logger has: ~Logger (x2 dtor slots), log, warn, error, get_level — at least 4
    _assert_vtable(logger, min_entries=4)

    # No pure-virtual methods in Logger
    for entry in logger.vtable:
        assert entry.func_addr is not None, (
            f"Logger vtable slot {entry.slot} should not be pure virtual"
        )
        assert entry.func_addr > 0


def _assert_inherit_rtti(binary) -> None:
    """Shape → Polygon → Rectangle → Square: 3-level single inheritance chain."""
    classes = binary.classes
    for name in ("Shape", "Polygon", "Rectangle", "Square"):
        assert name in classes, f"expected '{name}' in classes, got: {list(classes)}"

    shape = classes["Shape"]
    polygon = classes["Polygon"]
    rectangle = classes["Rectangle"]
    square = classes["Square"]

    # Base-class chain
    assert shape.base_classes == []
    assert "Shape" in polygon.base_classes
    assert "Polygon" in rectangle.base_classes
    assert "Rectangle" in square.base_classes

    # No multiple/virtual inheritance anywhere in this hierarchy
    for cls in (shape, polygon, rectangle, square):
        assert not cls.has_multiple_inheritance, (
            f"{cls.name}.has_multiple_inheritance should be False"
        )
        assert not cls.has_virtual_inheritance, (
            f"{cls.name}.has_virtual_inheritance should be False"
        )

    # Derived-class back-fill (computed in _load_classes after all classes load)
    assert "Polygon" in shape.derived_classes, (
        "Shape.derived_classes should include Polygon"
    )
    assert "Rectangle" in polygon.derived_classes, (
        "Polygon.derived_classes should include Rectangle"
    )
    assert "Square" in rectangle.derived_classes, (
        "Rectangle.derived_classes should include Square"
    )
    assert square.derived_classes == []

    # All four classes have vtables; leaf class (Square) has at least as many
    # slots as the root (Shape) since it inherits all virtual methods.
    for cls in (shape, polygon, rectangle, square):
        _assert_vtable(cls, min_entries=1)

    assert len(square.vtable) >= len(shape.vtable), (
        "Square should have at least as many vtable slots as Shape"
    )

    # Shape has pure-virtual methods; confirm at least one pure-virtual slot
    pure_slots = [e for e in shape.vtable if e.func_addr is None]
    assert len(pure_slots) >= 1, (
        "Shape should have at least one pure-virtual vtable slot"
    )


def _assert_diamond_rtti(binary) -> None:
    """Vehicle ←(virt) Car, Vehicle ←(virt) Boat, Car+Boat → Amphibious."""
    classes = binary.classes
    for name in ("Vehicle", "Car", "Boat", "Amphibious"):
        assert name in classes, f"expected '{name}' in classes, got: {list(classes)}"

    vehicle = classes["Vehicle"]
    car = classes["Car"]
    boat = classes["Boat"]
    amphibious = classes["Amphibious"]

    # Base-class relationships
    assert vehicle.base_classes == []
    assert "Vehicle" in car.base_classes
    assert "Vehicle" in boat.base_classes
    assert "Car" in amphibious.base_classes
    assert "Boat" in amphibious.base_classes

    # Amphibious inherits from two direct bases → multiple inheritance
    assert amphibious.has_multiple_inheritance, (
        "Amphibious should have has_multiple_inheritance=True"
    )

    # Car and Boat use `virtual Vehicle` → virtual inheritance
    assert car.has_virtual_inheritance, "Car should have has_virtual_inheritance=True"
    assert boat.has_virtual_inheritance, "Boat should have has_virtual_inheritance=True"

    # Derived-class back-fill
    assert "Car" in vehicle.derived_classes, (
        "Vehicle.derived_classes should include Car"
    )
    assert "Boat" in vehicle.derived_classes, (
        "Vehicle.derived_classes should include Boat"
    )
    assert "Amphibious" in car.derived_classes, (
        "Car.derived_classes should include Amphibious"
    )
    assert "Amphibious" in boat.derived_classes, (
        "Boat.derived_classes should include Amphibious"
    )

    # All four classes have vtables
    for cls in (vehicle, car, boat, amphibious):
        _assert_vtable(cls, min_entries=1)


# ---------------------------------------------------------------------------
# Ghidra (pyghidra / dragon backend, Ghidra >= 12)
# ---------------------------------------------------------------------------


class TestRTTIGhidra:
    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        from binocular import Ghidra

        if not Ghidra.is_installed():
            pytest.skip("Ghidra not installed")

    def test_simple(self, make_cpp):
        from binocular import Ghidra

        with Ghidra("rtti_simple") as g:
            g.analyze()
            _assert_simple_rtti(g.binary)

    def test_inherit(self, make_cpp):
        from binocular import Ghidra

        with Ghidra("rtti_inherit") as g:
            g.analyze()
            _assert_inherit_rtti(g.binary)

    def test_diamond(self, make_cpp):
        from binocular import Ghidra

        with Ghidra("rtti_diamond") as g:
            g.analyze()
            _assert_diamond_rtti(g.binary)


# ---------------------------------------------------------------------------
# Rizin
# ---------------------------------------------------------------------------


class TestRTTIRizin:
    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        from binocular import Rizin

        with Rizin("rtti_simple") as g:
            if not g.is_installed():
                pytest.skip("Rizin not installed")

    def test_simple(self, make_cpp):
        from binocular import Rizin

        with Rizin("rtti_simple") as g:
            g.analyze()
            _assert_simple_rtti(g.binary)

    def test_inherit(self, make_cpp):
        from binocular import Rizin

        with Rizin("rtti_inherit") as g:
            g.analyze()
            _assert_inherit_rtti(g.binary)

    def test_diamond(self, make_cpp):
        from binocular import Rizin

        with Rizin("rtti_diamond") as g:
            g.analyze()
            _assert_diamond_rtti(g.binary)


# ---------------------------------------------------------------------------
# Binary Ninja
# ---------------------------------------------------------------------------


class TestRTTIBinaryNinja:
    @pytest.fixture(autouse=True)
    def _skip_if_missing(self):
        from binocular import BinaryNinja

        if not BinaryNinja.is_installed():
            pytest.skip("Binary Ninja not installed")

    def test_simple(self, make_cpp):
        from binocular import BinaryNinja

        with BinaryNinja("rtti_simple") as g:
            g.analyze()
            _assert_simple_rtti(g.binary)

    def test_inherit(self, make_cpp):
        from binocular import BinaryNinja

        with BinaryNinja("rtti_inherit") as g:
            g.analyze()
            _assert_inherit_rtti(g.binary)

    def test_diamond(self, make_cpp):
        from binocular import BinaryNinja

        with BinaryNinja("rtti_diamond") as g:
            g.analyze()
            _assert_diamond_rtti(g.binary)
