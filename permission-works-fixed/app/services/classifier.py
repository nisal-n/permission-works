STATUS_COMMANDS = {
    "Release","Cancel","Complete","Close","Approve","Reject","Activate","Deactivate",
    "Confirm","Freeze","Unfreeze","Hold","Unhold","Start","Stop","Finish","Post",
    "Void","Unvoid","Reopen","Submit","Reschedule","Reassign"
}

def classify_projections_with_ai(traces):
    """
    Rule-based classification:
      - If any CRUD (POST/PATCH/DELETE) -> Full
      - OR if any status change (methodName ∈ STATUS_COMMANDS) -> Full
      - Else -> Read
    Only projections ending with 'Handling' are considered.
    """
    proj_methods = {}
    for t in traces:
        proj = t.get('projection')
        if not proj or not proj.endswith("Handling"):
            continue
        if proj not in proj_methods:
            proj_methods[proj] = set()

        method = t.get('method')
        method_name = t.get('methodName') or ""

        if method in ['POST', 'PATCH', 'DELETE']:
            proj_methods[proj].add('CRUD')
        if method_name in STATUS_COMMANDS or t.get('isStatusChange'):
            proj_methods[proj].add('STATUS')

    result_list = []
    for proj, access_types in proj_methods.items():
        access = 'full' if ('CRUD' in access_types or 'STATUS' in access_types) else 'read'
        result_list.append({"projection": proj, "access": access})
    return result_list
