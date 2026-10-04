# Assumptions (all to be validated with fraud practitioners / legal counsel)
- Both legs of a payment expose the same reference (RRN/UTR) on every modelled rail.
- Banks can link inbound to outbound credits locally (lineage), at least approximately.
- Golden window = 60 minutes (`api/complaints.py`); lien/action durations: A1-A3 24h, A4 12h, A5 72h (`models/case.py`).
- A4 "two approvers plus senior sign-off" is read as two L2 approvers AND one senior approver (three people).
- A1 (monitoring) is auto-approved; it creates no hold or freeze.
- Sandbox API keys, in-memory case storage and a single process are sandbox conveniences only.
- Epoch = UTC calendar date; matching accepts current and previous epoch.
- All data is synthetic. No compliance claim is made.
