"""تولید فهرست مسیرها از AST، بدون راه‌اندازی برنامه یا دست‌زدن به پایگاه داده."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "src/netagent/api"
rows = []
for source in [*sorted(API.glob("*_routes.py")), API / "routes.py", ROOT / "src/netagent/main.py"]:
    tree = ast.parse(source.read_text())
    prefix = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "APIRouter":
            prefix = next((ast.literal_eval(k.value) for k in node.keywords if k.arg == "prefix"), "")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in {"get", "post", "put", "patch", "delete"}):
                continue
            method = decorator.func.attr.upper()
            path = prefix + ast.literal_eval(decorator.args[0])
            body = ast.unparse(node)
            operation = next((ast.literal_eval(k.value) for k in decorator.keywords if k.arg == "summary"), node.name)
            access = "پایگاه داده"
            if path in {"/", "/docs", "/api/docs", "/healthz"}:
                level, identity, access, sensitivity = "Public", "همه", "بدون دادهٔ خصوصی", "کم"
            elif path.endswith("/enroll") or "/register" in path:
                level, identity, sensitivity = "Enrollment", "دارندهٔ توکن ثبت‌نام یا اثبات هویت درخواست", "بالا"
            elif path.startswith("/api/agent/"):
                level, identity, sensitivity = "Agent", "فقط عامل احرازهویت‌شده و منابع خودش", "بالا"
            else:
                identity, sensitivity = "فقط توکن مدیر", "بالا"
                level = "Admin Read Only" if method == "GET" else "Admin Full"
                if any(v in path for v in ("screenshot", "console", "/audit", "/settings")):
                    level = "Admin Full"
                if method == "POST" and path.startswith(("/api/tools/", "/api/scans", "/api/hosts/discover", "/api/jobs/investigation", "/api/investigations")):
                    level = "Admin Diagnostic"
            if any(v in body for v in ("execute_tool(", "host_discovery(", "run_investigation(", "ask_question(")):
                access += " + ابزار/مدل محدودشده"
            if any(v in body for v in ("create_diagnostic_task(", "create_admin", "console_service.", "task_service.")):
                access += " + صف تسک عامل"
            auth = "بدون توکن مدیر" if level in {"Public", "Enrollment"} else "Bearer، رد در Backend"
            rows.append((path, method, operation, auth, identity, level, access, sensitivity))

header = """# ماتریس دسترسی API

این فهرست از کد مسیرها با `uv run python scripts/access_matrix.py` تولید می‌شود.
در معماری فعلی یک توکن مدیر با اختیار کامل وجود دارد؛ سه سطح Admin زیر طبقه‌بندی عملیات‌اند، نه ادعای وجود سه نوع توکن یا RBAC جداگانه. عامل و هویت enrollment هرگز مجوز مدیر ندارند. guard مشترک روی routerهای legacy/admin/dashboard اعمال می‌شود؛ آزمون `test_access_matrix.py` همهٔ مسیرهای آن‌ها را بدون توکن، با توکن نامعتبر و با توکن عامل فراخوانی می‌کند.

Public فقط liveness و رابط مستندات/SPA است. `/health` جزئیات حساس دارد و به توکن مدیر نیاز دارد. Swagger و `/openapi.json` سیاست عمومی قبلی را حفظ می‌کنند؛ حاوی تعریف قرارداد هستند، نه دادهٔ runtime یا اعتبارنامه. ثبت‌نام با سقف بدنهٔ ۶۴ KiB و محدودیت نرخ محافظت می‌شود؛ claim به اثبات هویت، تأیید مدیر، زمان انقضا و مصرف یک‌باره وابسته است. Agent فقط با credential خودش heartbeat/inventory/result می‌دهد؛ مالکیت task پیش از ذخیره بررسی می‌شود.

| روش | مسیر | عملیات | احراز هویت | هویت مجاز | حداقل سطح عملیات | دسترسی | حساسیت |
|---|---|---|---|---|---|---|---|
"""
for path, method, *rest in sorted(rows):
    header += "| " + " | ".join([method, f"`{path}`", *(str(v).replace("|", "/") for v in rest)]) + " |\n"
header += "| GET/HEAD | `/openapi.json` | تعریف قرارداد FastAPI | عمومی | همه | Public | بدون دادهٔ runtime | کم |\n"
header += "| GET/HEAD | `/dashboard/*` | پوسته و فایل‌های SPA | عمومی؛ داده از API محافظت‌شده | همه برای پوسته | Public | فایل‌های build | کم |\n"
(ROOT / "docs/access-matrix.fa.md").write_text(header)
print(f"{len(rows)} مسیر تابعی + OpenAPI و SPA ثبت شد.")
