Real-log false-positive regression cases (nginx combined format).

Expected with the fix applied:
- a_expired_login.log      -> 0 detections (token expired, user logged back in)
- b_shared_mobile_ip.log   -> 0 detections (one denied user + 3 staff on one shared IP)
- c_real_attack.log        -> 1 block_defiance (case/encoding/dot-segment bypass)
- d_route_only_attack.log  -> 1 block_defiance (Medicare-style sibling-route hunt)

Run: python3 ingest.py tests/real_log_fp/<file>.log
