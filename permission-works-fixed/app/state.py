# Simple in-memory state store (kept from original single-file app).
trace_log = []
ai_summary = []
is_tracing = False

# Tracked resources
lobby_pages = {}         # { lobby_id: {"title": str|None} }
quick_reports = set()    # {"QuickReport706301"}
workflows = set()        # {"DemoCreateTaskPOExample"}
reports = {}             # {"CUSTOMER_ORDER_CONF_REP": "CustomerOrderConfRep"}
