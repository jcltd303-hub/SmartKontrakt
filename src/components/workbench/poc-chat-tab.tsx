import type { PocStatus } from "@/lib/audit/types";
import type { PocChatPurpose } from "@/lib/audit/poc-chat-clean";
import type { SavedPocChatSummary } from "@/lib/audit/poc-chat-store.server";
import { chatCodeIsRunnable, splitChatSegments } from "./poc-chat-helpers";
import {
  ArrowRight,
  Bot,
  Download,
  FilePlus2,
  FolderOpen,
  Loader2,
  MessagesSquare,
  Paperclip,
  Play,
  Save,
  Send,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  User,
  Wrench,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type {
  PocChatMessage,
  PocChatPendingAttachment,
} from "./use-workbench-controller";

/**
 * PoC Chat tab — a conversation with the OpenRouter models about
 * the PoC for the currently loaded contract. Two lanes, shown in
 * the header: conversation rides the "chat" purpose model, exploit
 * generation (Suggest a PoC / Fix the last run) rides the "code"
 * purpose model. State lives in the workbench controller; this
 * component renders it and wires the powers the panel has: attach
 * files to a turn, Apply a suggested draft to the Interactive
 * editor, Run a draft through the canonical single-PoC path, and
 * save / load / export conversations (saved chats persist in the
 * archive — migration 0019). The chat itself never executes
 * anything — every Apply/Run is a click here.
 */

export type PocChatTabProps = {
  messages: PocChatMessage[];
  sending: boolean;
  running: boolean;
  onSend: (text: string, purpose?: PocChatPurpose) => void;
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
  pendingAttachments: PocChatPendingAttachment[];
  onAddFiles: (files: FileList | File[]) => void;
  onRemoveAttachment: (id: string) => void;
  models: { chat: string; code: string } | null;
  openRouterUsage: {
    configured: boolean;
    key: {
      label: string | null;
      usage: number | null;
      usageDaily: number | null;
      usageWeekly: number | null;
      usageMonthly: number | null;
      limit: number | null;
      limitRemaining: number | null;
      isFreeTier: boolean | null;
      rateLimitRequests: number | null;
      rateLimitInterval: string | null;
    } | null;
    keyError: string | null;
    probe: { ok: boolean; model: string; latencyMs: number | null; error: string | null };
  } | null;
  contextEstimate: { tokens: number; turns: number };
  savedChats: SavedPocChatSummary[];
  currentChatId: string | null;
  saving: boolean;
  onSave: () => void;
  onLoadChat: (id: string) => void;
  onDeleteChat: (id: string) => void;
  onNewChat: () => void;
  onExport: () => void;
};

type OpenRouterUsageProp = PocChatTabProps["openRouterUsage"];

/**
 * One-line rendering of the server's OpenRouter ledger + probe
 * (getOpenRouterUsageFn). Every number is the key's own /auth/key
 * report; a missing half is shown as unavailable rather than guessed.
 */
function formatOpenRouterUsage(usage: NonNullable<OpenRouterUsageProp>): string {
  if (!usage.configured) {
    return "OpenRouter: no API key configured on the server — AI calls fall back to templates.";
  }
  const parts: string[] = ["OpenRouter:"];
  if (usage.key) {
    const k = usage.key;
    if (k.usage !== null) {
      parts.push(
        `$${k.usage.toFixed(2)} used` +
          (k.usageDaily !== null ? ` ($${k.usageDaily.toFixed(2)} today)` : ""),
      );
    }
    if (k.limit !== null) {
      parts.push(
        `$${(k.limitRemaining ?? 0).toFixed(2)} of $${k.limit.toFixed(2)} credit left`,
      );
    }
    parts.push(k.isFreeTier ? "free tier" : "funded");
    if (k.rateLimitRequests !== null) {
      parts.push(
        `limit ${k.rateLimitRequests} req${k.rateLimitInterval ? `/${k.rateLimitInterval}` : ""}`,
      );
    }
  } else {
    parts.push(`usage unavailable${usage.keyError ? ` (${usage.keyError})` : ""}`);
  }
  parts.push(
    usage.probe.ok
      ? `test call ok${usage.probe.latencyMs !== null ? ` in ${(usage.probe.latencyMs / 1000).toFixed(1)}s` : ""}`
      : `test call FAILED${usage.probe.error ? `: ${usage.probe.error}` : ""}`,
  );
  return parts.join(" · ");
}

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
  pendingAttachments,
  onAddFiles,
  onRemoveAttachment,
  models,
  openRouterUsage,
  contextEstimate,
  savedChats,
  currentChatId,
  saving,
  onSave,
  onLoadChat,
  onDeleteChat,
  onNewChat,
  onExport,
}: PocChatTabProps) {
  const [composer, setComposer] = useState("");
  const [appliedKeys, setAppliedKeys] = useState<Record<string, boolean>>({});
  const [savedOpen, setSavedOpen] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

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
        <div className="flex flex-wrap items-center gap-2 text-[#f4efe6] font-semibold">
          <MessagesSquare className="w-4 h-4 text-[#e8a54b]" />
          <span>PoC Chat</span>
          <span className="ml-auto flex flex-wrap items-center gap-1.5">
            <button
              onClick={onSave}
              disabled={saving || messages.length === 0}
              title={
                currentChatId
                  ? "Update this saved conversation"
                  : "Save this conversation to the archive"
              }
              className="px-2.5 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              {saving ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Save className="w-3.5 h-3.5 text-[#e8a54b]" />
              )}
              <span>{currentChatId ? "Saved — update" : "Save"}</span>
            </button>
            <button
              onClick={() => setSavedOpen((v) => !v)}
              title="Conversations saved in the archive"
              className="px-2.5 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors"
            >
              <FolderOpen className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>Saved ({savedChats.length})</span>
            </button>
            <button
              onClick={onExport}
              disabled={messages.length === 0}
              title="Download this conversation as Markdown"
              className="px-2.5 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>Export</span>
            </button>
            <button
              onClick={onNewChat}
              disabled={messages.length === 0 && !currentChatId}
              title="Start a fresh conversation (the current one stays saved if you saved it)"
              className="px-2.5 py-1.5 bg-[#2a251c] hover:bg-[#3a3428] border border-[#3a3428] text-[#f4efe6] font-bold text-xs rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <FilePlus2 className="w-3.5 h-3.5 text-[#e8a54b]" />
              <span>New</span>
            </button>
          </span>
        </div>
        <p className="text-xs text-[#a39886]">
          Chat with the model about this contract's PoC — ask for a strategy, a complete draft, a
          fix, or an audit of the draft. The chat sees: {contextLine}. It never runs anything
          itself: Apply and Run on a suggested draft are your clicks, through the same editor and
          run path as the Interactive tab.
        </p>
        <p className="text-[11px] font-mono text-[#a39886]">
          {models ? (
            <>
              converse: <span className="text-[#f4efe6]">{models.chat}</span> · exploit
              generation: <span className="text-[#f4efe6]">{models.code}</span> ·{" "}
            </>
          ) : null}
          context window: ≈{contextEstimate.tokens.toLocaleString()} tokens (system + last{" "}
          {contextEstimate.turns} turn{contextEstimate.turns === 1 ? "" : "s"}, 40 kept)
        </p>
        {openRouterUsage ? (
          <p className="text-[11px] font-mono text-[#a39886]">
            {formatOpenRouterUsage(openRouterUsage)}
          </p>
        ) : null}
        {savedOpen && (
          <div className="border border-[#3a3428] rounded-lg bg-[#12110e] p-2 flex flex-col gap-1 max-h-56 overflow-y-auto">
            {savedChats.length === 0 && (
              <p className="text-xs text-[#a39886] p-2">
                No saved conversations yet — Save keeps this one in the archive.
              </p>
            )}
            {savedChats.map((chat) => (
              <div
                key={chat.id}
                className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-[#26231c]"
              >
                <button
                  onClick={() => {
                    onLoadChat(chat.id);
                    setSavedOpen(false);
                  }}
                  className="flex-1 text-left min-w-0"
                  title="Load this conversation"
                >
                  <span className="block text-xs text-[#f4efe6] truncate">
                    {chat.title}
                    {chat.id === currentChatId ? " (open)" : ""}
                  </span>
                  <span className="block text-[10px] font-mono text-[#655d4e] truncate">
                    {chat.messageCount} messages · {new Date(chat.updatedAt).toLocaleString()}
                    {chat.address ? ` · ${chat.address}` : ""}
                  </span>
                </button>
                <button
                  onClick={() => onDeleteChat(chat.id)}
                  title="Delete this saved conversation"
                  className="p-1.5 text-[#a39886] hover:text-rose-400 transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
        {/* Quick actions */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() =>
              topFinding &&
              onSend(
                `Write a complete Foundry fork PoC for the top finding — [${topFinding.severity.toUpperCase()}] ${topFinding.title} (detector: ${topFinding.detector}). Return exactly one complete fenced solidity block containing an executable Test contract.`,
                "code",
              )
            }
            disabled={!topFinding || sending}
            title={
              topFinding
                ? "Ask the code model for a PoC for the highest-severity loaded finding"
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
                "code",
              )
            }
            disabled={!lastRunFailed || sending}
            title={
              lastRunFailed
                ? "Send the last run's logs + draft to the code model and ask for a corrected draft"
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
              hands the model the logs and the draft together. Attach a file with the paperclip
              when the model needs to see it, and <span className="text-[#e8a54b]">Save</span>{" "}
              keeps the conversation in the archive.
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
                  {msg.attachments && msg.attachments.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {msg.attachments.map((att, k) => (
                        <span
                          key={k}
                          className="flex items-center gap-1 text-[10px] font-mono bg-[#12110e] border border-[#3a3428] rounded px-1.5 py-0.5 text-[#a39886]"
                        >
                          <Paperclip className="w-3 h-3" />
                          {att.name}
                        </span>
                      ))}
                    </div>
                  )}
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
                {msg.model && <span className="text-[#655d4e]">via {msg.model}</span>}
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
        {pendingAttachments.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {pendingAttachments.map((att) => (
              <span
                key={att.id}
                className="flex items-center gap-1.5 text-[11px] font-mono bg-[#12110e] border border-[#3a3428] rounded px-2 py-1 text-[#f4efe6]"
              >
                <Paperclip className="w-3 h-3 text-[#e8a54b]" />
                {att.name}
                <span className="text-[#655d4e]">{Math.ceil(att.content.length / 1024)} KB</span>
                <button
                  onClick={() => onRemoveAttachment(att.id)}
                  title="Remove this attachment"
                  className="text-[#a39886] hover:text-rose-400 transition-colors"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>
        )}
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
          <span className="flex items-center gap-3 text-[10px] font-mono text-[#655d4e]">
            <button
              onClick={() => fileRef.current?.click()}
              title="Attach a text file (source, draft, logs — up to 4 per message, 256 KB each)"
              className="flex items-center gap-1 text-[#a39886] hover:text-[#e8a54b] transition-colors"
            >
              <Paperclip className="w-3.5 h-3.5" />
              <span>Attach file</span>
            </button>
            <input
              ref={fileRef}
              type="file"
              multiple
              accept=".sol,.txt,.md,.json,.ts,.tsx,.js,.jsx,.py,.csv,.log,text/*"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files.length > 0) onAddFiles(e.target.files);
                e.target.value = "";
              }}
            />
            <span>Enter to send · Shift+Enter for a newline</span>
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
