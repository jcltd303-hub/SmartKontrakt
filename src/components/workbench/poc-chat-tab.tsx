import type { PocStatus } from "@/lib/audit/types";
import { chatCodeIsRunnable, splitChatSegments } from "./poc-chat-helpers";
import {
  ArrowRight,
  Bot,
  Loader2,
  MessagesSquare,
  Play,
  Send,
  ShieldCheck,
  Sparkles,
  Terminal,
  User,
  Wrench,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { PocChatMessage } from "./use-workbench-controller";

/**
 * PoC Chat tab — a conversation with the OpenRouter "chat" model
 * about the PoC for the currently loaded contract. All state lives
 * in the workbench controller (session-only); this component renders
 * it and wires the three powers the chat has: Apply a suggested
 * draft to the Interactive editor, Run a draft through the canonical
 * single-PoC path, and the quick-action prompts. The chat itself
 * never executes anything — every Apply/Run is a click here.
 */

export type PocChatTabProps = {
  messages: PocChatMessage[];
  sending: boolean;
  running: boolean;
  onSend: (text: string) => void;
  onApplyCode: (code: string) => void;
  onRunCode: (code: string) => void;
  onOpenInteractive: () => void;
  address: string;
  chainId: string;
  contractName: string;
  findingCount: number;
  topFinding: { severity: string; title: string; detector: string } | null;
  hasDraft: boolean;
  lastRunStatus: PocStatus | null;
  lastRunFailed: boolean;
};

export function PocChatTab({
  messages,
  sending,
  running,
  onSend,
  onApplyCode,
  onRunCode,
  onOpenInteractive,
  address,
  chainId,
  contractName,
  findingCount,
  topFinding,
  hasDraft,
  lastRunStatus,
  lastRunFailed,
}: PocChatTabProps) {
  const [composer, setComposer] = useState("");
  const [appliedKeys, setAppliedKeys] = useState<Record<string, boolean>>({});
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, sending]);

  const submit = () => {
    const text = composer.trim();
    if (!text || sending) return;
    setComposer("");
    onSend(text);
  };

  const contextLine = [
    address ? `target ${address} (${chainId})` : "no target address selected",
    `contract ${contractName}`,
    findingCount > 0 ? `${findingCount} finding${findingCount === 1 ? "" : "s"} loaded` : "no findings loaded",
    hasDraft ? "a PoC draft in the Interactive editor" : "no PoC draft yet",
    lastRunStatus ? `last run: ${lastRunStatus}` : "no PoC run yet",
  ].join(" · ");

  return (
    <div className="p-6 max-w-7xl mx-auto flex flex-col gap-4">
      {/* Header / context */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-2">
        <div className="flex items-center gap-2 text-[#f4efe6] font-semibold">
          <MessagesSquare className="w-4 h-4 text-[#e8a54b]" />
          <span>PoC Chat</span>
        </div>
        <p className="text-xs text-[#a39886]">
          Chat with the model about this contract's PoC — ask for a strategy, a complete draft, a
          fix, or an audit of the draft. The chat sees: {contextLine}. It never runs anything
          itself: Apply and Run on a suggested draft are your clicks, through the same editor and
          run path as the Interactive tab.
        </p>
        {/* Quick actions */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() =>
              topFinding &&
              onSend(
                `Write a complete Foundry fork PoC for the top finding — [${topFinding.severity.toUpperCase()}] ${topFinding.title} (detector: ${topFinding.detector}). Return exactly one complete fenced solidity block containing an executable Test contract.`,
              )
            }
            disabled={!topFinding || sending}
            title={
              topFinding
                ? "Ask for a PoC for the highest-severity loaded finding"
                : "Load a contract with findings first (Workbench tab)"
            }
            className="px-3 py-1.5 bg-[#e8a54b] hover:bg-[#d6933c] text-[#12110e] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Suggest a PoC</span>
          </button>
          <button
            onClick={() =>
              onSend(
                "Audit the current PoC draft (in your context) against the target source and findings: does it actually prove the claimed vulnerability? Call out false-positive traps — assertions that would pass even without the bug — fabricated interfaces, and weak or missing assertions. If the draft is sound, say so plainly.",
              )
            }
            disabled={!hasDraft || sending}
            title={
              hasDraft
                ? "Ask the model to review the draft currently in the Interactive editor"
                : "The Interactive editor holds no PoC draft to audit"
            }
            className="px-3 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Audit this PoC</span>
          </button>
          <button
            onClick={() =>
              onSend(
                "The last run of the current PoC draft did not pass — its status and log tail are in your context. Diagnose the failure from the logs and return a corrected, complete draft in exactly one fenced solidity block, changing only what the failure requires.",
              )
            }
            disabled={!lastRunFailed || sending}
            title={
              lastRunFailed
                ? "Send the last run's logs + draft and ask for a corrected draft"
                : "Enabled after a run fails or errors"
            }
            className="px-3 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Wrench className="w-3.5 h-3.5 text-rose-400" />
            <span>Fix the last run</span>
          </button>
        </div>
      </div>

      {/* Conversation */}
      <div
        ref={listRef}
        className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-3 min-h-[320px] max-h-[62vh] overflow-y-auto"
      >
        {messages.length === 0 && !sending && (
          <div className="text-xs text-[#a39886] leading-relaxed">
            <p className="text-[#f4efe6] font-semibold text-sm mb-1">No conversation yet.</p>
            <p>
              Ask anything about proving the findings on this contract — or use{" "}
              <span className="text-[#e8a54b]">Suggest a PoC</span> to get a complete draft, then
              Apply it to the Interactive editor or Run it right from the reply. Follow-ups keep
              the context: after a run, <span className="text-[#e8a54b]">Fix the last run</span>{" "}
              hands the model the logs and the draft together.
            </p>
          </div>
        )}
        {messages.map((msg, i) => {
          if (msg.role === "run") {
            return (
              <div
                key={i}
                className="bg-[#12110e] border border-[#3a3428] border-l-4 border-l-[#e8a54b] rounded-lg p-3 font-mono text-xs text-[#a39886] whitespace-pre-wrap"
              >
                <div className="flex items-center gap-1.5 text-[#e8a54b] font-bold mb-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>RUN RESULT</span>
                </div>
                {msg.content}
              </div>
            );
          }
          if (msg.role === "user") {
            return (
              <div key={i} className="flex justify-end">
                <div className="max-w-[85%] bg-[#3a2c14] border border-[#e8a54b]/30 rounded-xl rounded-br-sm p-3 text-sm text-[#f4efe6] whitespace-pre-wrap">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#e8a54b] mb-1">
                    <User className="w-3 h-3" />
                    <span>YOU</span>
                  </div>
                  {msg.content}
                </div>
              </div>
            );
          }
          return (
            <div
              key={i}
              className="max-w-[92%] bg-[#26231c] border border-[#3a3428] rounded-xl rounded-bl-sm p-3 text-sm text-[#f4efe6] flex flex-col gap-2"
            >
              <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#a39886]">
                <Bot className="w-3 h-3 text-[#e8a54b]" />
                <span>POC ASSISTANT</span>
              </div>
              {splitChatSegments(msg.content).map((seg, j) => {
                if (seg.kind === "text") {
                  return (
                    <p key={j} className="whitespace-pre-wrap leading-relaxed">
                      {seg.text.trim()}
                    </p>
                  );
                }
                const key = `${i}:${j}`;
                const runnable = chatCodeIsRunnable(seg.code);
                const applied = Boolean(appliedKeys[key]);
                return (
                  <div key={j} className="flex flex-col gap-1.5">
                    <pre className="bg-[#12110e] border border-[#3a3428] rounded-lg p-3 font-mono text-xs text-[#f4efe6] overflow-x-auto whitespace-pre">
                      {seg.code.replace(/^\n+|\n+$/g, "")}
                    </pre>
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={() => {
                          onApplyCode(seg.code);
                          setAppliedKeys((prev) => ({ ...prev, [key]: true }));
                        }}
                        className="px-2.5 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors"
                        title="Write this draft into the Interactive tab's PoC editor"
                      >
                        <span>{applied ? "Applied ✓" : "Apply to editor"}</span>
                      </button>
                      <button
                        onClick={() => onRunCode(seg.code)}
                        disabled={!runnable || running}
                        title={
                          runnable
                            ? "Run this draft on the fork through the workbench's PoC path"
                            : "No executable Test contract in this block — the harness would run zero tests (no_tests)"
                        }
                        className="px-2.5 py-1.5 bg-[#e8a54b] hover:bg-[#d6933c] text-[#12110e] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
                      >
                        {running ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Play className="w-3.5 h-3.5" />
                        )}
                        <span>{runnable ? "Run" : "Run — no executable test"}</span>
                      </button>
                      {applied && (
                        <button
                          onClick={onOpenInteractive}
                          className="text-[11px] font-mono text-[#e8a54b] hover:text-[#f0b25e] flex items-center gap-1"
                        >
                          <span>Open in Interactive</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          );
        })}
        {sending && (
          <div className="flex items-center gap-2 text-xs text-[#a39886] font-mono">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-[#e8a54b]" />
            <span>Waiting for the model… (the free lane can take a while)</span>
          </div>
        )}
      </div>

      {/* Composer */}
      <div className="bg-[#1c1a16] border border-[#3a3428] rounded-xl p-4 shadow-sm flex flex-col gap-2">
        <textarea
          value={composer}
          onChange={(e) => setComposer(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
          rows={3}
          placeholder="Ask about the PoC — e.g. “Why would this test pass even without the bug?” or “Write the PoC for the reentrancy finding”"
          className="w-full font-mono text-xs bg-[#12110e] border border-[#3a3428] text-[#f4efe6] rounded-lg p-3 focus:outline-none focus:border-[#e8a54b]"
        />
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono text-[#655d4e]">
            Enter to send · Shift+Enter for a newline · session-only, nothing is saved
          </span>
          <button
            onClick={submit}
            disabled={sending || composer.trim().length === 0}
            className="px-3 py-1.5 bg-[#e8a54b] hover:bg-[#d6933c] text-[#12110e] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {sending ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Send className="w-3.5 h-3.5" />
            )}
            <span>Send</span>
          </button>
        </div>
      </div>
    </div>
  );
}
