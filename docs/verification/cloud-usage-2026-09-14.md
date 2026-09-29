# Cloud usage monitoring — September 14, 2026

The existing Supabase Usage dashboard supplies visible monitoring without a new service or paid subscription. On September 14 at approximately 09:17 UTC, regular authenticated Chrome showed the Context Relay project on the Free plan, for the August 16–September 16 billing cycle. No billing, subscription, project, notification or credential setting was changed.

Open the [Context Relay usage view](https://supabase.com/dashboard/org/ttbvkrzpfnxgxozawxnb/usage?projectRef=brvzuycnxoswdzzipgvx). The project filter identifies attributable usage; switch to **All projects** to check shared organization quotas. Database size is explicitly shown as a per-project allowance. The organization summary's highest database utilization must not be attributed to Context Relay.

| Item | Context Relay display | Allowance shown in organization view |
| --- | --- | --- |
| Database size | 27.64 MB in detail; 0.029 GB in summary | 0.5 GB per project |
| Edge Function invocations | 8 | 500,000 per billing cycle |
| Egress | 0 GB, rounded display | 5 GB per billing cycle |
| Cached egress | 0 GB, rounded display | 5 GB per billing cycle |
| Monthly active users | 0 displayed | 50,000 per billing cycle |
| Storage size | 0 GB, rounded display | 1 GB |
| Realtime messages | 0 displayed | 2,000,000 per billing cycle |
| Realtime concurrent peak connections | 0 displayed | 200 |

The organization view showed 21,984 Edge invocations and 0.029 GB egress, with no quota exceeded. These organization totals include other projects; they are not Context Relay activity. Zero or rounded values and delayed counters do not prove absence of traffic or successful hosted behavior. The page states that summary metrics can lag by an hour and some activity metrics by 24 hours.

Before and after each hosted acceptance batch, record the billing cycle, selected project, project database size, organization quota headroom and test request counts in that batch's evidence. Use the existing bounded test workloads and stop the batch if a quota warning appears or its remaining allowance cannot cover the planned work. Investigate repeated requests before resuming. Do not upgrade, add paid resources or clean up unrelated project data to finish a test. Retain the before/after observations even when counters have not refreshed; take the later reading when available instead of relabeling unchanged counters as zero usage.

Supabase's [cost-control documentation](https://supabase.com/docs/guides/platform/cost-control) states that Free-plan usage is not charged, while quota excess can restrict service. Its Spend Cap is a Pro-plan feature and is not a custom budget or threshold notification system. No Spend Cap configuration or alert delivery was claimed or tested here. The [usage documentation](https://supabase.com/docs/guides/platform/manage-your-usage) describes the individual metrics.

This is a dated operational baseline and a repeatable monitoring procedure, not a load test, a billing guarantee after future plan changes, or hosted acceptance. The selected Usage tab was kept available in Chrome. The local evidence transcription is `.superpowers/sdd/2026-09-14-pr16-windows-shared-acceptance/cloud-usage-observation-2026-09-14.json`; it deliberately excludes unrelated project names and credentials. No background monitoring job was created.
