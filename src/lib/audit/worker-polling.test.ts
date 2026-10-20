import test from "node:test";
import assert from "node:assert/strict";
import { startWorkerPolling } from "./worker-polling.ts";

test("hidden worker monitor performs neither initial nor repeated polls", (t) => {
  t.mock.timers.enable({ apis: ["setInterval"] });
  let polls = 0;
  const stop = startWorkerPolling(false, () => { polls++; });
  t.mock.timers.tick(20_000);
  stop();
  assert.equal(polls, 0);
});

test("active worker monitor polls immediately and every five seconds until cleanup", (t) => {
  t.mock.timers.enable({ apis: ["setInterval"] });
  let polls = 0;
  const stop = startWorkerPolling(true, () => { polls++; });
  assert.equal(polls, 1);
  t.mock.timers.tick(4999);
  assert.equal(polls, 1);
  t.mock.timers.tick(1);
  assert.equal(polls, 2);
  stop();
  t.mock.timers.tick(20_000);
  assert.equal(polls, 2);
});

test("monitor reactivation starts a fresh poll cycle without retaining the previous interval", (t) => {
  t.mock.timers.enable({ apis: ["setInterval"] });
  let polls = 0;
  const poll = () => { polls++; };
  const firstStop = startWorkerPolling(true, poll);
  firstStop();
  const hiddenStop = startWorkerPolling(false, poll);
  t.mock.timers.tick(10_000);
  assert.equal(polls, 1);
  hiddenStop();
  const finalStop = startWorkerPolling(true, poll);
  assert.equal(polls, 2);
  t.mock.timers.tick(5000);
  assert.equal(polls, 3);
  finalStop();
});
