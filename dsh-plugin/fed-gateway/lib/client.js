window.__ModuleLoader__.load({ id: "hive-fed-gateway", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/client/index.tsx
var index_exports = {};
__export(index_exports, {
  HiveGatewayRow: () => HiveGatewayRow,
  apply: () => apply,
  inject: () => inject
});
module.exports = __toCommonJS(index_exports);
var import_react = require("react");
var import_jsx_runtime = require("react/jsx-runtime");
var NS = "hive-gateway";
var SLOT = "plugins.row.config";
var SEAT_KEY = "hive-fed-gateway#hive-fed-gateway/host";
var FIELDS = [
  {
    field: "port",
    label: "\u8054\u90A6\u7AEF\u53E3",
    hint: "1\u201365535\uFF1B\u4FDD\u5B58\u540E\u7ACB\u5373\u91CD\u542F\u76D1\u542C\uFF0C\u5DF2\u8FDE\u63A5\u7684\u4E3B\u673A\u4F1A\u81EA\u52A8\u91CD\u8FDE\u3002",
    placeholder: "3081",
    fallback: "3081",
    parse: (text) => {
      if (text.trim() === "") return { kind: "clear" };
      const port = Number(text.trim());
      if (!Number.isInteger(port) || port < 1 || port > 65535) return void 0;
      return { kind: "set", value: port };
    }
  },
  {
    field: "bindHost",
    label: "\u76D1\u542C\u5730\u5740",
    hint: "\u672C\u673A\u6F14\u793A\u7528 127.0.0.1\uFF1B\u5C40\u57DF\u7F51\u6216\u7ECF OpenP2P \u7EC4\u7F51\u7684\u90E8\u7F72\u6539 0.0.0.0\u3002",
    placeholder: "127.0.0.1",
    fallback: "127.0.0.1",
    parse: (text) => text.trim() === "" ? { kind: "clear" } : { kind: "set", value: text.trim() }
  }
];
function useScope(scope) {
  const [snapshot, setSnapshot] = (0, import_react.useState)(() => scope.getSnapshot());
  (0, import_react.useEffect)(() => {
    setSnapshot(scope.getSnapshot());
    return scope.subscribe(() => setSnapshot(scope.getSnapshot()));
  }, [scope]);
  return snapshot;
}
function userCarries(user, field) {
  return typeof user === "object" && user !== null && Object.prototype.hasOwnProperty.call(user, field);
}
function useCardForm(scope, snapshot) {
  const [drafts, setDrafts] = (0, import_react.useState)({});
  const [saving, setSaving] = (0, import_react.useState)(false);
  const [failed, setFailed] = (0, import_react.useState)(false);
  const specOf = (field) => FIELDS.find((spec) => spec.field === field);
  const draftOf = (field) => drafts[field];
  const planOf = (field, draft) => {
    if (draft.kind === "clear") return { kind: "clear" };
    return specOf(field)?.parse(draft.text);
  };
  const plans = Object.entries(drafts).map(([field, draft]) => planOf(field, draft));
  const discard = () => {
    setDrafts({});
    setFailed(false);
  };
  const save = () => {
    if (saving) return;
    if (plans.some((plan) => plan === void 0)) return;
    const writes = Object.entries(drafts).map(([field, draft]) => {
      const plan = planOf(field, draft);
      return () => plan?.kind === "set" ? scope.set(field, plan.value) : scope.unset(field);
    });
    setSaving(true);
    setFailed(false);
    void (async () => {
      try {
        for (const write of writes) await write();
        setDrafts({});
      } catch {
        setFailed(true);
      } finally {
        setSaving(false);
      }
    })();
  };
  return {
    text: (field) => {
      const draft = draftOf(field);
      if (draft !== void 0) return draft.kind === "clear" ? "" : draft.text;
      const stored = snapshot.value?.[field];
      if (stored === void 0 || stored === null) return specOf(field)?.fallback ?? "";
      return String(stored);
    },
    overridden: (field) => {
      const draft = draftOf(field);
      if (draft !== void 0) return draft.kind === "set";
      return userCarries(snapshot.user, field);
    },
    invalid: (field) => {
      const draft = draftOf(field);
      if (draft === void 0) return false;
      return planOf(field, draft) === void 0;
    },
    dirty: Object.keys(drafts).length > 0,
    invalidAny: plans.some((plan) => plan === void 0),
    saving,
    failed,
    edit: (field, text) => setDrafts((current) => ({ ...current, [field]: { kind: "set", text } })),
    reset: (field) => setDrafts((current) => ({ ...current, [field]: { kind: "clear" } })),
    save,
    discard
  };
}
var LABEL = { fontSize: 13, fontWeight: 600, color: "var(--dsw-alias-label-primary, inherit)" };
var HINT = { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-secondary, rgba(128,128,128,.9))" };
var ERROR = { ...HINT, color: "var(--dsw-alias-state-error-primary, inherit)" };
var INPUT = {
  width: "100%",
  boxSizing: "border-box",
  padding: "5px 8px",
  border: "0.5px solid var(--dsw-alias-border-l3, rgba(128,128,128,.45))",
  borderRadius: 6,
  background: "transparent",
  color: "inherit",
  font: "inherit"
};
function Field(props) {
  const { spec, form, readOnly } = props;
  const bad = form.invalid(spec.field);
  return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { style: { display: "grid", gridTemplateColumns: "minmax(120px, 168px) minmax(0, 1fr)", gap: "12px", alignItems: "start" }, children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", { style: LABEL, children: spec.label }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", { style: HINT, children: spec.hint })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
        "input",
        {
          style: bad ? { ...INPUT, borderColor: "var(--dsw-alias-state-error-primary, rgba(200,60,60,.8))" } : INPUT,
          value: form.text(spec.field),
          placeholder: spec.placeholder,
          disabled: readOnly,
          "aria-invalid": bad || void 0,
          onChange: (event) => form.edit(spec.field, event.target.value),
          onKeyDown: (event) => {
            if (event.key === "Enter") form.save();
          }
        }
      ),
      bad ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", { style: ERROR, children: "\u8FD9\u4E2A\u53D6\u503C\u4E0D\u88AB\u63A5\u53D7\uFF0C\u4FDD\u5B58\u5DF2\u963B\u6B62" }) : null,
      form.overridden(spec.field) ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { style: { display: "flex", alignItems: "center", gap: 8, marginTop: 4 }, children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { style: { ...HINT, border: "0.5px solid var(--dsw-alias-border-l4, rgba(128,128,128,.45))", borderRadius: 4, padding: "0 4px" }, children: "\u5DF2\u8986\u76D6" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
          "button",
          {
            type: "button",
            onClick: () => form.reset(spec.field),
            disabled: readOnly,
            style: { ...HINT, background: "none", border: 0, padding: 0, cursor: readOnly ? "default" : "pointer", textDecoration: "underline" },
            children: "\u6062\u590D\u9ED8\u8BA4"
          }
        )
      ] }) : null
    ] })
  ] });
}
function Card(props) {
  const { form, snapshot } = props;
  const readOnly = !snapshot.writable;
  const saveStyle = {
    padding: "4px 12px",
    borderRadius: 6,
    border: "0.5px solid var(--dsw-alias-border-l3, rgba(128,128,128,.45))",
    background: "var(--dsw-alias-bg-layer-3, rgba(128,128,128,.12))",
    color: "inherit",
    font: "inherit",
    cursor: "pointer"
  };
  return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { style: { display: "flex", flexDirection: "column", gap: 12, padding: "4px 0" }, children: [
    readOnly ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { style: HINT, children: "\u8FD9\u6761\u8FDE\u63A5\u628A\u504F\u597D\u4FDD\u5B58\u5728\u672C\u8FDB\u7A0B\u5185\uFF0C\u6539\u52A8\u65E0\u6CD5\u5199\u5165 Host \u7684\u8BBE\u7F6E\u6587\u6863\u3002" }) : null,
    FIELDS.map((spec) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Field, { spec, form, readOnly }, spec.field)),
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }, children: [
      form.failed ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { style: ERROR, children: "\u4FDD\u5B58\u672A\u751F\u6548\uFF0C\u8349\u7A3F\u5DF2\u4FDD\u7559\uFF1A\u8BF7\u68C0\u67E5\u53D6\u503C\u6216\u91CD\u8BD5\u3002" }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { style: HINT, children: form.dirty ? "\u6709\u672A\u4FDD\u5B58\u7684\u6539\u52A8" : "\u5DF2\u4E0E Host \u540C\u6B65" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { style: { display: "flex", gap: 8 }, children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", { type: "button", onClick: form.discard, disabled: !form.dirty || form.saving, style: saveStyle, children: "\u653E\u5F03" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
          "button",
          {
            type: "button",
            onClick: form.save,
            disabled: readOnly || !form.dirty || form.invalidAny || form.saving,
            style: { ...saveStyle, opacity: readOnly || !form.dirty || form.invalidAny ? 0.5 : 1 },
            children: form.saving ? "\u4FDD\u5B58\u4E2D\u2026" : "\u4FDD\u5B58"
          }
        )
      ] })
    ] })
  ] });
}
function Summary(props) {
  const value = props.snapshot.value ?? {};
  const port = value.port ?? 3081;
  const bindHost = value.bindHost ?? "127.0.0.1";
  const overridden = userCarries(props.snapshot.user, "port") || userCarries(props.snapshot.user, "bindHost");
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_jsx_runtime.Fragment, { children: `\u76D1\u542C ${String(bindHost)}:${String(port)}${overridden ? " \xB7 \u5DF2\u8986\u76D6" : ""}` });
}
function HiveGatewayRow(props) {
  const { scope, view } = props;
  const snapshot = useScope(scope);
  const form = useCardForm(scope, snapshot);
  if (snapshot.status === "unavailable") return null;
  if (view === "summary") return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Summary, { snapshot });
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Card, { form, snapshot });
}
var inject = ["slots", "locale", "remote", "settingsScope"];
function apply(ctx) {
  const c = ctx;
  if (c.slots === void 0 || c.settingsScope === void 0) return;
  const slots = c.slots;
  const scope = c.settingsScope.bind({ namespace: NS });
  const face = c.settingsScope.describe();
  let mounted;
  const sync = () => {
    const served = new Set(face.getSnapshot().view?.namespaces.map((view) => view.ns) ?? []);
    if (served.has(NS) && mounted === void 0) {
      mounted = slots.inject(SLOT, () => slots.register({
        name: SLOT,
        key: SEAT_KEY,
        inject: () => ({ scope })
      }, HiveGatewayRow));
    } else if (!served.has(NS) && mounted !== void 0) {
      mounted();
      mounted = void 0;
    }
  };
  const unsubscribe = face.subscribe(sync);
  const teardown = () => {
    unsubscribe();
    mounted?.();
    mounted = void 0;
  };
  void face.ensure();
  sync();
  c.effect?.(() => teardown, "hive-fed-gateway: row configuration seat");
}

return module.exports; } });
//# sourceMappingURL=client.js.map
