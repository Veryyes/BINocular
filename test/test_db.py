from sqlalchemy.orm import Session
from binocular import Ghidra, Backend
from binocular.db import BinaryORM

def test_insert_two(make):
    Backend.set_engine("sqlite://")

    bin1 = "example"
    bin2 = "example2"
    bins = [bin1, bin2]

    assert Ghidra.is_installed()
    
    for bin in bins:
        with Ghidra() as g:
            g.load(bin)
            b = g.binary
            
            with Session(Backend.engine) as s:
                b.db_add(s)
                s.commit()
    
    with Session(Backend.engine) as s:
        x = s.query(BinaryORM).all()
        assert len(x) == 2

    Backend.engine.dispose()
    Backend.engine = None
        
def test_insert_multiple(make):
    Backend.set_engine("sqlite://")

    bin1 = "example"
    bin2 = "example2"
    bin3 = "example3"
    bins = [bin1, bin2, bin3]

    assert Ghidra.is_installed()
    
    with Ghidra() as g:
        for bin in bins:
            g.load(bin)
            b = g.binary
            
            with Session(Backend.engine) as s:
                b.db_add(s)
                s.commit()
            g.clear()
    
    with Session(Backend.engine) as s:
        res = s.query(BinaryORM).all()
        assert len(res) == 3

        assert len(set([b.architecture for b in res]) ^ {'x86', 'ARM'}) == 0

    Backend.engine.dispose()
    Backend.engine = None