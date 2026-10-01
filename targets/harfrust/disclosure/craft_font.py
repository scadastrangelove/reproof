#!/usr/bin/env python3
"""Build a minimal TTF with two identical RTL cursive lookups via feaLib."""
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont

FEA = """\
@GDEF_Base = [Ba Meem];
@GDEF_Mark = [Fathah];

table GDEF {
    GlyphClassDef @GDEF_Base, , @GDEF_Mark, ;
} GDEF;

feature curs {
    lookup curs_rtl_1 {
        lookupflag RightToLeft IgnoreMarks;
        pos cursive Ba <anchor 0 0> <anchor 500 0>;
        pos cursive Meem <anchor 0 0> <anchor 500 0>;
    } curs_rtl_1;

    lookup curs_rtl_2 {
        lookupflag RightToLeft IgnoreMarks;
        pos cursive Ba <anchor 0 0> <anchor 500 0>;
        pos cursive Meem <anchor 0 0> <anchor 500 0>;
    } curs_rtl_2;
} curs;
"""

def main():
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder([".notdef", "Ba", "Fathah", "Meem"])
    fb.setupCharacterMap({
        0x0628: "Ba",
        0x064E: "Fathah",
        0x0645: "Meem",
    })

    glyphs = {}
    for name in [".notdef", "Ba", "Fathah", "Meem"]:
        pen = TTGlyphPen(None)
        pen.moveTo((0, 0))
        pen.lineTo((500, 0))
        pen.lineTo((500, 700))
        pen.lineTo((0, 700))
        pen.closePath()
        glyphs[name] = pen.glyph()
    fb.setupGlyf(glyphs)

    fb.setupHorizontalMetrics({
        ".notdef": (500, 0),
        "Ba": (600, 0),
        "Fathah": (0, 0),
        "Meem": (600, 0),
    })
    fb.setupHorizontalHeader()
    fb.setupNameTable({"familyName": "CursivePoC", "styleName": "Regular"})
    fb.setupOS2()
    fb.setupPost()
    fb.setupHead(unitsPerEm=1000)

    fb.addOpenTypeFeatures(FEA)

    out = "crafted_cursive.ttf"
    fb.font.save(out)
    print(f"Saved {out}")

    # Verify
    f = TTFont(out)
    gpos = f["GPOS"].table
    print(f"GPOS lookups: {len(gpos.LookupList.Lookup)}")
    for i, lk in enumerate(gpos.LookupList.Lookup):
        print(f"  [{i}] type={lk.LookupType} flag=0x{lk.LookupFlag:04x} subs={len(lk.SubTable)}")
        for st in lk.SubTable:
            print(f"      coverage: {st.Coverage.glyphs}, records: {len(st.EntryExitRecord)}")
    gdef = f["GDEF"].table
    print(f"GDEF classes: {gdef.GlyphClassDef.classDefs}")
    print("OK")

if __name__ == "__main__":
    main()
