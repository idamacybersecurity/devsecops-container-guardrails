"""Phase 2 timing hook. Active only when BOTO_TIMING_LOG is set."""
import os
if os.environ.get("BOTO_TIMING_LOG"):
    try:
        import json, threading, time
        from botocore import handlers

        _LOG = os.environ["BOTO_TIMING_LOG"]
        _RUN = os.environ.get("RUN_ID", "norun")
        _lock = threading.Lock()

        def _write(rec):
            rec["run"] = _RUN
            rec["pid"] = os.getpid()
            with _lock, open(_LOG, "a") as f:
                f.write(json.dumps(rec) + "\n")

        def _before(context=None, **kw):
            if context is not None:
                context["_t0"] = time.perf_counter()
                context["_wall0"] = time.time()

        def _after(model=None, context=None, **kw):
            if context is None or "_t0" not in context:
                return
            _write({"svc": model.service_model.service_name,
                    "op": model.name,
                    "start": context["_wall0"],
                    "dur_s": round(time.perf_counter() - context["_t0"], 4),
                    "ok": True})

        def _error(context=None, exception=None, event_name="", **kw):
            if context is None or "_t0" not in context:
                return
            parts = event_name.split(".")
            _write({"svc": parts[1] if len(parts) > 2 else "?",
                    "op": parts[2] if len(parts) > 2 else "?",
                    "start": context["_wall0"],
                    "dur_s": round(time.perf_counter() - context["_t0"], 4),
                    "ok": False, "err": type(exception).__name__})

        handlers.BUILTIN_HANDLERS.append(("before-call.*.*", _before))
        handlers.BUILTIN_HANDLERS.append(("after-call.*.*", _after))
        handlers.BUILTIN_HANDLERS.append(("after-call-error.*.*", _error))
    except Exception as e:  # never break the program being measured
        print("timing hook disabled:", e)
