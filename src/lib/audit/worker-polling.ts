/** Schedule the worker monitor separately from the retained batch runner. */
export function startWorkerPolling(active: boolean, poll: () => void, intervalMs = 5000): () => void {
  if (!active) return () => undefined;
  poll();
  const timer = setInterval(poll, intervalMs);
  return () => clearInterval(timer);
}
