# Analytics queries

Manual SQL queries for the Supabase Studio SQL editor. Run as needed — there is intentionally no dashboard, no PostHog, no Mixpanel. The point is to keep usage observable without adding tooling overhead before there is anything to observe.

All queries assume the only persisted activity is in the `scans` table. There is no separate `users` table — NextAuth stores sessions as JWTs and the GitHub username/email is written directly to `scans.user_id`. "Signups" are therefore approximated as "first scan ever per user."

---

## 1. Signups per day (proxy: first-scan-per-user per day)

```sql
select
  date_trunc('day', first_scan_at)::date as day,
  count(*) as new_users
from (
  select user_id, min(scanned_at) as first_scan_at
  from scans
  group by user_id
) t
group by 1
order by 1 desc;
```

---

## 2. Scans per day

```sql
select
  date_trunc('day', scanned_at)::date as day,
  count(*) as scans,
  count(distinct user_id) as distinct_users
from scans
group by 1
order by 1 desc;
```

---

## 3. Distinct users with at least 1 scan in the last 7 days

```sql
select count(distinct user_id) as active_users_7d
from scans
where scanned_at >= now() - interval '7 days';
```

Variant — list them with their scan counts:

```sql
select user_id, count(*) as scans_last_7d
from scans
where scanned_at >= now() - interval '7 days'
group by user_id
order by scans_last_7d desc;
```

---

## 4. Simple 7-day retention (returned to scan after their first day)

A user is "retained" if they have a scan on a different calendar day than their first-ever scan, within 7 days of that first scan.

```sql
with first_scans as (
  select user_id, min(scanned_at) as first_scan_at
  from scans
  group by user_id
),
returners as (
  select fs.user_id
  from first_scans fs
  join scans s on s.user_id = fs.user_id
  where s.scanned_at::date <> fs.first_scan_at::date
    and s.scanned_at <= fs.first_scan_at + interval '7 days'
  group by fs.user_id
)
select
  (select count(*) from first_scans) as total_users,
  (select count(*) from returners) as retained_7d_users,
  case
    when (select count(*) from first_scans) = 0 then null
    else round(100.0 * (select count(*) from returners) / (select count(*) from first_scans), 1)
  end as retention_7d_pct;
```

---

## 5. Top scanned repos (sanity check on what people are actually testing)

Useful before posting publicly — if everyone scans the same demo repo, that signals the landing page may be steering them there.

```sql
select owner || '/' || repo as repository, count(*) as scans, count(distinct user_id) as distinct_users
from scans
where scanned_at >= now() - interval '30 days'
group by 1
order by scans desc
limit 20;
```

---

## When to run these

- Before any distribution push — capture a fresh snapshot in `docs/baseline-metrics.md`.
- ~7 days after a distribution push — see if traffic converted into actual scans, not just landing-page visits.
- Before reopening the billing work — confirm the user-count threshold from `docs/baseline-metrics.md` is met.

If you find yourself running these more than once a week, that is the signal to add a real analytics tool, not before.
