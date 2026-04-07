# PowerAuth — Activation Code Unique Constraint Migration Performance

This folder contains performance test scripts for the `pa_activation` table migration
introduced in issue [#2004](https://github.com/wultra/powerauth-server/issues/2004)
(unique compound index on `application_id` + `activation_code`).

The scripts measure the time required to:
1. Add a `NOT NULL` constraint on `activation_code`
2. Build a new unique compound index `(application_id, activation_code)`
3. Drop the old non-unique single-column index on `activation_code`

## Test Environment

All tests were run on **macOS with Apple Silicon (ARM64)** using [Colima](https://github.com/abiosoft/colima) as the container runtime.
Images without native ARM64 support ran under QEMU x86_64 emulation.

| DB | Version | Image | macOS/ARM64 |
|----|---------|-------|:-----------:|
| PostgreSQL | 18.2 | `postgres:18.2` | ✅ native |
| Oracle | 23ai Free (26ai) | `gvenzl/oracle-free:latest` | ✅ native |
| Azure SQL Edge | 2.0.0 | `mcr.microsoft.com/azure-sql-edge:latest` | ✅ native |
| MS SQL Server | 2022 CU24 | `mcr.microsoft.com/mssql/server:2022-CU24-ubuntu-22.04` | ⚠️ QEMU |
| Oracle | 19c Enterprise | `container-registry.oracle.com/database/enterprise:19.3.0.0.0` | ⚠️ QEMU |

Dataset: **10,000,000 rows** in `pa_activation_perf_test`.

## Results

### Migration steps (production-relevant)

| Step | Operation | PostgreSQL 18 | Oracle 19c ³ | Oracle 23ai ⁴ | MSSQL 2022 ³ | Azure SQL Edge ⁴ |
|------|-----------|:-------------:|:------------:|:-------------:|:------------:|:----------------:|
| 1 | ADD NOT NULL on `activation_code` | 1.8 s | 11.2 s | 1.2 s | ~0 ms ¹ | — ¹ |
| 2 | ADD UNIQUE (`application_id`, `activation_code`) | **18.9 s** | **251.9 s** | **6.9 s** | **88.8 s** | **22.0 s** |
| 3 | DROP old non-unique index | 0.01 s | 0.18 s | 0.08 s | 0.012 s | 0.000 s |

> ¹ MSSQL/Azure SQL Edge handle ADD NOT NULL as a near-instant metadata-only operation when no NULL
> values exist in the column. PostgreSQL and Oracle perform a full table scan to validate.
>
> ³ Ran under QEMU emulation (linux/amd64 on Apple Silicon) — results may not reflect native performance.
>
> ⁴ Ran natively on Apple Silicon (linux/arm64) — not directly comparable to QEMU results.

### Full results including data generation

| Step | Operation | PostgreSQL 18 | Oracle 19c ³ | Oracle 23ai ⁴ | MSSQL 2022 ³ | Azure SQL Edge ⁴ |
|------|-----------|:-------------:|:------------:|:-------------:|:------------:|:----------------:|
| 0 | Data generation (10M rows) ² | 284.7 s | 1 842 s | 174 s | 650.9 s | 90.9 s |
| 1 | ADD NOT NULL on `activation_code` | 1.8 s | 11.2 s | 1.2 s | ~0 ms | — |
| 2 | ADD UNIQUE (`application_id`, `activation_code`) | 18.9 s | 251.9 s | 6.9 s | 88.8 s | 22.0 s |
| 3 | DROP old non-unique index | 0.01 s | 0.18 s | 0.08 s | 0.012 s | 0.000 s |

> ² Data generation times reflect differences in the test script approach
> (PostgreSQL: single `INSERT … SELECT`; MSSQL: cross-join tally CTE; Oracle: batched
> PL/SQL `FORALL` loop). They are **not** a DB performance indicator.

## Analysis

**Step 2 — ADD UNIQUE (the critical migration operation):**
- Oracle 23ai Free (native ARM64) is the fastest at **~7 s** — fastest of all tested.
- PostgreSQL takes **~19 s** — fast B-tree index build.
- Azure SQL Edge (native ARM64) takes **~22 s** — comparable to PostgreSQL.
- MSSQL 2022 takes **~89 s** under QEMU emulation — likely faster on native x86 hardware.
- Oracle 19c takes **~252 s** under QEMU emulation — likely faster on native x86 hardware.

**Step 1 — ADD NOT NULL:**
- MSSQL and Azure SQL Edge detect there are no NULLs and apply the constraint as a metadata change only (~0 ms).
- Oracle 23ai Free and PostgreSQL validate with a full scan in ~1.2–1.8 s.
- Oracle 19c validates with a full scan in ~11.2 s.

**Step 3 — DROP old index:**
- All three databases drop the index near-instantly (metadata operation).

**Overall migration downtime estimate on a 10M-row production table:**

| DB | Estimated downtime |
|----|-------------------|
| Oracle 23ai Free | < 1 min |
| PostgreSQL 18 | < 1 min |
| Azure SQL Edge 2.0 | < 1 min |
| MSSQL 2022 | ~2 min (QEMU) |
| Oracle 19c | ~5 min (QEMU) |

## How to Reproduce

Each subfolder contains three scripts:

| Script | Purpose |
|--------|---------|
| `pa_activation_perf_test_create_db.sql` | Create schema/user/tablespace |
| `pa_activation_perf_test.sql` | Run the benchmark |
| `pa_activation_perf_test_drop_db.sql` | Drop schema/user/tablespace |

See the header comment in each script for the exact `psql` / `sqlplus` / `sqlcmd` invocation.
