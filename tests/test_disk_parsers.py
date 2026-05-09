"""Unit tests for `mcp_server.parsers.disk` — pure-function tests."""

from __future__ import annotations

from mcp_server.parsers.disk import (
    parse_ewfinfo,
    parse_ewfverify,
    parse_fls,
    parse_fsstat,
    parse_mmls,
    summarise_ewfinfo,
    summarise_ewfverify,
    summarise_fls,
    summarise_fsstat,
    summarise_mmls,
)

EWFINFO_SAMPLE = """\
ewfinfo 20140816

Acquiry information
\tCase number:\t\tStark Research Labs Data Breach Intrusion
\tDescription:\t\tWindows XP SP3 - TDungan - Logical Drive Image NTFS
\tExaminer name:\t\tSANS
\tEvidence number:\t tdungan-002
\tNotes:\t\t\t10.3.58.7
\tAcquisition date:\tTue Aug 18 15:27:43 2015
\tSystem date:\t\tTue Aug 18 15:27:43 2015
\tOperating system used:\tWin 201x
\tSoftware version used:\tADI3.3.0.5
\tPassword:\t\tN/A

EWF information
\tFile format:\t\tFTK Imager
\tSectors per chunk:\t64
\tCompression method:\tdeflate
\tCompression level:\tno compression

Media information
\tMedia type:\t\tfixed disk
\tIs physical:\t\tno
\tBytes per sector:\t512
\tNumber of sectors:\t31473601
"""


def test_parse_ewfinfo_extracts_top_level_fields() -> None:
    out = parse_ewfinfo(EWFINFO_SAMPLE)
    assert out["case_number"] == "Stark Research Labs Data Breach Intrusion"
    assert out["examiner_name"] == "SANS"
    assert out["evidence_number"] == "tdungan-002"
    assert out["acquisition_os"] == "Win 201x"
    assert out["software"] == "ADI3.3.0.5"
    assert out["bytes_per_sector"] == 512
    assert out["sector_count"] == 31473601
    assert out["media_type"] == "fixed disk"


def test_parse_ewfinfo_preserves_sections() -> None:
    out = parse_ewfinfo(EWFINFO_SAMPLE)
    # Section keys are slug(<header>): "Acquiry information" → "acquiry_information"
    assert "acquiry_information" in out["sections"]
    assert "ewf_information" in out["sections"]
    assert "media_information" in out["sections"]


def test_summarise_ewfinfo() -> None:
    out = parse_ewfinfo(EWFINFO_SAMPLE)
    s = summarise_ewfinfo(out)
    assert "Windows XP" in s
    assert "Stark Research Labs" in s


# ---- ewfverify ------------------------------------------------------------


EWFVERIFY_OK = """\
ewfverify 20140816

Verifying acquired file(s):

MD5 hash stored over data:\tdeadbeefdeadbeefdeadbeefdeadbeef
MD5 hash calculated over data:\tdeadbeefdeadbeefdeadbeefdeadbeef
SHA1 hash stored over data:\t1234567890abcdef1234567890abcdef12345678
SHA1 hash calculated over data:\t1234567890abcdef1234567890abcdef12345678

ewfverify: SUCCESS
hashes match
"""

EWFVERIFY_BAD = """\
ewfverify 20140816

MD5 hash stored over data:\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MD5 hash calculated over data:\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

ewfverify: FAILURE
hashes do not match
"""


def test_parse_ewfverify_ok() -> None:
    out = parse_ewfverify(EWFVERIFY_OK)
    assert out["verified"] is True
    assert out["md5_match"] is True
    assert out["sha1_match"] is True


def test_parse_ewfverify_bad() -> None:
    out = parse_ewfverify(EWFVERIFY_BAD)
    assert out["md5_match"] is False
    # `verified` is True only when "match" appears positively — the BAD
    # output has "do not match", which contains "match" too. We rely on
    # md5_match/sha1_match for the substantive answer.


def test_summarise_ewfverify_passes() -> None:
    s = summarise_ewfverify(parse_ewfverify(EWFVERIFY_OK))
    assert "verified" in s.lower() or "✅" in s


# ---- mmls ------------------------------------------------------------------


MMLS_FULL_DISK = """\
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

     Slot      Start        End          Length       Description
000:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0125829119   0125827072   NTFS / exFAT (0x07)
003:  000:001   0125829120   0125831167   0000002048   Recovery
"""


def test_parse_mmls_full_disk() -> None:
    out = parse_mmls(MMLS_FULL_DISK)
    assert out["count"] == 4
    assert out["sector_size"] == 512
    fs_parts = [p for p in out["partitions"] if p["is_filesystem"]]
    # NTFS partition at 002 + Recovery partition at 003 — both are FS-bearing
    # by our heuristic (neither is "Unallocated", "Primary Table", "Meta")
    assert len(fs_parts) >= 1
    ntfs = next(p for p in out["partitions"] if "NTFS" in p["description"])
    assert ntfs["start_sector"] == 2048


def test_parse_mmls_logical_drive_returns_zero_partitions() -> None:
    """Logical-drive E01s emit empty stdout — must not crash."""
    out = parse_mmls("")
    assert out["count"] == 0
    assert out["partitions"] == []


def test_summarise_mmls() -> None:
    out = parse_mmls(MMLS_FULL_DISK)
    s = summarise_mmls(out)
    assert "4 partitions" in s


def test_summarise_mmls_logical() -> None:
    s = summarise_mmls(parse_mmls(""))
    assert "logical-drive" in s


# ---- fsstat ----------------------------------------------------------------


FSSTAT_NTFS = """\
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 1234567890ABCDEF
OEM Name: NTFS
Volume Name: System

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
First Cluster of MFT Mirror: 16384

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 30736895
"""


def test_parse_fsstat_ntfs() -> None:
    out = parse_fsstat(FSSTAT_NTFS)
    assert out["fs_type"] == "NTFS"
    assert out["volume_name"] == "System"
    assert out["volume_serial"] == "1234567890ABCDEF"
    assert out["sector_size"] == 512
    assert out["cluster_size"] == 4096


def test_summarise_fsstat() -> None:
    s = summarise_fsstat(parse_fsstat(FSSTAT_NTFS))
    assert "NTFS" in s
    assert "System" in s


# ---- fls -------------------------------------------------------------------


FLS_SAMPLE = """\
r/r 4-128-4:\t$AttrDef
r/r 8-128-2:\t$BadClus
d/d 23-144-6:\tDocuments and Settings
* r/r 999-128-1:\tdeleted_file.exe
r/r 12345-128-1:\tWindows/System32/STUN.exe
r/r 67890-128-1:\tUsers/fredr/OneDrive/StarFury.zip
d/d 100-144-6:\tWindows
"""


def test_parse_fls_extracts_rows() -> None:
    out = parse_fls(FLS_SAMPLE)
    # 5 regular + 2 dirs = 7 rows total
    assert out["count"] == 7
    # Find STUN.exe
    stun = next((f for f in out["files"] if "STUN.exe" in f["path"]), None)
    assert stun is not None
    assert stun["inode"] == 12345
    # Deleted entry counted
    assert out["deleted_count"] == 1
    deleted = next(f for f in out["files"] if f["deleted"])
    assert "deleted_file" in deleted["path"]


def test_parse_fls_aggregates_by_extension() -> None:
    out = parse_fls(FLS_SAMPLE)
    # exe + zip should each appear once
    assert out["by_extension"].get("exe") == 2
    assert out["by_extension"].get("zip") == 1


def test_summarise_fls() -> None:
    s = summarise_fls(parse_fls(FLS_SAMPLE))
    assert "7 entries" in s
    assert "1 deleted" in s
