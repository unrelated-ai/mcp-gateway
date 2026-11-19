import datetime
import json
import os
import sys

label, log = sys.argv[1:]
changed = False
created = datetime.datetime.now(datetime.timezone.utc).isoformat()

def send(value):
    print(json.dumps(value), flush=True)

def task():
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return dict(taskId="same-task", status="working", createdAt=created, lastUpdatedAt=now, ttlMs=60000)

for line in sys.stdin:
    body = json.loads(line)
    method, params = body["method"], body.get("params", {})
    with open(log, "a") as file:
        file.write(json.dumps(body) + "\n")
    if "id" not in body:
        continue
    assert method != "initialize", "native backend received initialize"
    assert params["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    result = {"resultType": "complete"}
    if method == "server/discover":
        result.update(supportedVersions=["2026-07-28"], capabilities={"tools": {"listChanged": True}, "resources": {"subscribe": True, "listChanged": True}, "prompts": {"listChanged": True}, "completions": {}, "extensions": {"io.modelcontextprotocol/tasks": {}}}, ttlMs=0, cacheScope="private")
        if label == "tools-only":
            result["capabilities"] = {"tools": {}}
    elif method == "tools/list":
        name = "whoami" if label == "mixed" else "echo"
        result["tools"] = [{"name": name, "inputSchema": {"type": "object", "properties": {"mode": {"type": "string", "x-mcp-header": "mode"}}}}]
        if changed:
            result["tools"].append({"name": "fresh", "inputSchema": {"type": "object"}})
    elif label == "tools-only" and method in ("resources/list", "prompts/list", "resources/templates/list"):
        raise AssertionError("unsupported catalog requested")
    elif method == "resources/list":
        result["resources"] = [{"uri": "test://same", "name": "resource"}]
    elif method == "resources/templates/list":
        result["resourceTemplates"] = [{"uriTemplate": "test://{id}", "name": "template"}]
    elif method == "prompts/list":
        result["prompts"] = [{"name": "prompt"}]
    elif method in ("tools/call", "resources/read", "prompts/get"):
        mode = params.get("arguments", {}).get("mode", "mrtr" if method != "tools/call" else "normal")
        if mode == "add-tool":
            changed = True
        if mode == "crash":
            os._exit(1)
        if mode == "wait":
            continue
        if mode == "task":
            result = dict(resultType="task", **task())
        elif mode == "mrtr" and "requestState" not in params:
            result = dict(resultType="input_required", requestState="same-state", inputRequests={"roots": {"method": "roots/list"}})
        else:
            if mode == "mrtr":
                assert params["requestState"] == "same-state"
                assert params["inputResponses"]["roots"] == {"roots": []}
            if method == "tools/call":
                result["content"] = [{"type": "text", "text": label}]
            elif method == "resources/read":
                result["contents"] = [{"uri": params["uri"], "text": label}]
            else:
                result["messages"] = [{"role": "user", "content": {"type": "text", "text": label}}]
    elif method == "completion/complete":
        result["completion"] = {"values": [label], "hasMore": False}
    elif method.startswith("tasks/"):
        assert params["taskId"] == "same-task"
        if method == "tasks/get":
            result.update(task(), ttlMs=120000, status="completed", result={"content": [{"type": "text", "text": label}]})
    elif method == "subscriptions/listen" and label != "tools-only":
        filters = params["notifications"]
        meta = {"io.modelcontextprotocol/subscriptionId": body["id"]}
        def notify(method, **params):
            send(dict(jsonrpc="2.0", method=method, params=dict(_meta=meta, **params)))
        notify("notifications/subscriptions/acknowledged", notifications=filters)
        for uri in filters.get("resourceSubscriptions", []):
            notify("notifications/resources/updated", uri=uri)
        for id in filters.get("taskIds", []):
            notify("notifications/tasks", **dict(task(), taskId=id, ttlMs=90000))
        if filters.get("toolsListChanged"):
            changed = True
            notify("notifications/tools/list_changed")
            result = dict(resultType="complete", _meta=meta)
        else:
            continue
    else:
        send(dict(jsonrpc="2.0", id=body["id"], error=dict(code=-32601, message="unsupported")))
        continue
    send(dict(jsonrpc="2.0", id=body["id"], result=result))
