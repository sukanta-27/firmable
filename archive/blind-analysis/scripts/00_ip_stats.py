"""Step 0. Per-IP context used by the concentration checks: how many records and
distinct ports each IP has in the whole file, and whether any of its records carries
the honeypot, cdn or cloud tag. Written to cache/ip_stats.<dataset>.parquet.
Run: uv run python archive/blind-analysis/scripts/00_ip_stats.py sample|full
"""

from _db import ROOT, connect

con, ds = connect()
out = ROOT / "archive" / "blind-analysis" / "cache"
out.mkdir(exist_ok=True)
path = out / f"ip_stats.{ds}.parquet"
con.execute(
    f"""COPY (
      SELECT ip,
             count(*) AS ip_records,
             count(DISTINCT port) AS ip_ports,
             bool_or(list_contains(tags, 'honeypot')) AS ip_honeypot,
             bool_or(list_contains(tags, 'cdn')) AS ip_cdn,
             bool_or(list_contains(tags, 'cloud')) AS ip_cloud
      FROM banner GROUP BY ip
    ) TO '{path}' (FORMAT parquet)"""
)
show_sql = f"""SELECT count(*) AS ips,
  count(*) FILTER (WHERE ip_ports >= 20) AS ips_20plus_ports,
  sum(ip_records) FILTER (WHERE ip_ports >= 20) AS records_on_20plus_port_ips,
  sum(ip_records) AS records,
  quantile_cont(ip_records, [0.5, 0.9, 0.99, 0.999]) AS rec_per_ip_q,
  max(ip_records) AS max_rec,
  count(*) FILTER (WHERE ip_honeypot) AS honeypot_ips
FROM '{path}'"""
print(con.sql(show_sql))
