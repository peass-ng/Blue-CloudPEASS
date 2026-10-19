import type { Schedule, ScheduleRule } from "./types";

const weekdays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
export const defaultRule = (): ScheduleRule => ({ frequency: "daily", time: "09:00" });

export function nextScheduleDate(schedule: Schedule): string {
  if (!schedule.next_run_at) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short",
    timeZone: schedule.timezone || "UTC" }).format(new Date(schedule.next_run_at));
}

export function scheduleDescription(schedule: Schedule): string {
  if (!schedule.rules?.length) return `Every ${schedule.interval_hours || 168} hours`;
  return schedule.rules.map(rule => {
    if (rule.frequency === "weekly") return `${(rule.weekdays || []).map(day => weekdays[day]).join(", ")} at ${rule.time}`;
    if (rule.frequency === "monthly") return `Monthly on day ${rule.day_of_month} at ${rule.time}`;
    return `Daily at ${rule.time}`;
  }).join("; ") + ` · ${schedule.timezone || "UTC"}`;
}

export function ScheduleRules({ rules, timezone, onRules, onTimezone }: {
  rules: ScheduleRule[]; timezone: string;
  onRules: (rules: ScheduleRule[]) => void; onTimezone: (zone: string) => void;
}) {
  const supported = (Intl as typeof Intl & { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.("timeZone")
    || ["Europe/Madrid", "Europe/London", "America/New_York", "America/Los_Angeles", "Asia/Tokyo"];
  const zones = [...new Set(["UTC", timezone, ...supported])];
  const update = (index: number, rule: ScheduleRule) => onRules(rules.map((old, i) => i === index ? rule : old));
  return <div className="form">
    <label>Time zone
      <select aria-label="Schedule time zone" value={timezone} onChange={event => onTimezone(event.target.value)}>
        {zones.map(zone => <option key={zone} value={zone}>{zone.replaceAll("_", " ")}</option>)}
      </select>
    </label>
    {rules.map((rule, index) => <fieldset key={index} className="form">
      <legend>Rule {index + 1}</legend>
      <div className="form-columns">
        <label>Repeat
          <select aria-label={`Rule ${index + 1} frequency`} value={rule.frequency} onChange={event => {
            const frequency = event.target.value as ScheduleRule["frequency"];
            update(index, { frequency, time: rule.time,
              ...(frequency === "weekly" ? { weekdays: [0] } : frequency === "monthly" ? { day_of_month: 1 } : {}) });
          }}>
            <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option>
          </select>
        </label>
        <label>Time
          <input aria-label={`Rule ${index + 1} time`} type="time" required value={rule.time}
            onChange={event => update(index, { ...rule, time: event.target.value })} />
        </label>
      </div>
      {rule.frequency === "weekly" && <div role="group" aria-label={`Rule ${index + 1} weekdays`} className="assessment-category-grid">
        {weekdays.map((name, day) => <label className="checkbox" key={name}>
          <input type="checkbox" checked={rule.weekdays?.includes(day) || false} onChange={event =>
            update(index, { ...rule, weekdays: event.target.checked ? [...(rule.weekdays || []), day].sort() : (rule.weekdays || []).filter(value => value !== day) })} />{name}
        </label>)}
      </div>}
      {rule.frequency === "monthly" && <label>Day of the month
        <select aria-label={`Rule ${index + 1} day of month`} value={rule.day_of_month || 1}
          onChange={event => update(index, { ...rule, day_of_month: Number(event.target.value) })}>
          {Array.from({ length: 31 }, (_, i) => i + 1).map(day => <option key={day} value={day}>{day}</option>)}
        </select>
        <span className="muted small">Shorter months use their last day.</span>
      </label>}
      {rules.length > 1 && <button type="button" className="text-button" aria-label={`Remove rule ${index + 1}`}
        onClick={() => onRules(rules.filter((_, i) => i !== index))}>Remove rule</button>}
    </fieldset>)}
    <button type="button" className="button" disabled={rules.length >= 20} onClick={() => onRules([...rules, defaultRule()])}>Add another rule</button>
    <p className="muted small">Each rule adds a run time. Rules at the same time start one scan. Times follow the selected time zone; daylight saving gaps move the run forward, and repeated times run once. Account quotas still apply.</p>
  </div>;
}
