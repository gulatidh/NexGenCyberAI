export type NotifType = "success" | "error" | "warning" | "info";

export interface AppNotification {
  id: string;
  type: NotifType;
  message: string;
  detail?: string;
  timestamp: string;
  read: boolean;
}

const STORAGE_KEY = "nexgen_notifications";
const MAX = 100;
type Listener = () => void;
const _listeners: Listener[] = [];

export function subscribeNotifications(fn: Listener): () => void {
  _listeners.push(fn);
  return () => { const i = _listeners.indexOf(fn); if (i >= 0) _listeners.splice(i, 1); };
}

function _emit() { _listeners.forEach((fn) => fn()); }

export function getNotifications(): AppNotification[] {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); } catch { return []; }
}

export function addNotification(n: Omit<AppNotification, "id" | "timestamp" | "read">) {
  const all = getNotifications();
  const entry: AppNotification = { ...n, id: `${Date.now()}-${Math.random().toString(36).slice(2)}`, timestamp: new Date().toISOString(), read: false };
  all.unshift(entry);
  if (all.length > MAX) all.length = MAX;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
  _emit();
}

export function markAllRead() {
  const all = getNotifications().map((n) => ({ ...n, read: true }));
  localStorage.setItem(STORAGE_KEY, JSON.stringify(all));
  _emit();
}

export function clearNotifications() {
  localStorage.removeItem(STORAGE_KEY);
  _emit();
}

export function unreadCount(): number {
  return getNotifications().filter((n) => !n.read).length;
}
