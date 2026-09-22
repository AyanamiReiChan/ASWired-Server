export const DEFAULT_AGENT_REPORT_INTERVAL = "5";

export function agentReportInterval(customValue?: string): string {
  const interval = Number(customValue?.trim());
  return Number.isFinite(interval) && interval >= 1
    ? String(interval)
    : DEFAULT_AGENT_REPORT_INTERVAL;
}
