# ماتریس دسترسی API

این فهرست از کد مسیرها با `uv run python scripts/access_matrix.py` تولید می‌شود.
در معماری فعلی یک توکن مدیر با اختیار کامل وجود دارد؛ سه سطح Admin زیر طبقه‌بندی عملیات‌اند، نه ادعای وجود سه نوع توکن یا RBAC جداگانه. عامل و هویت enrollment هرگز مجوز مدیر ندارند. guard مشترک روی routerهای legacy/admin/dashboard اعمال می‌شود؛ آزمون `test_access_matrix.py` همهٔ مسیرهای آن‌ها را بدون توکن، با توکن نامعتبر و با توکن عامل فراخوانی می‌کند.

Public فقط liveness و رابط مستندات/SPA است. `/health` جزئیات حساس دارد و به توکن مدیر نیاز دارد. Swagger و `/openapi.json` سیاست عمومی قبلی را حفظ می‌کنند؛ حاوی تعریف قرارداد هستند، نه دادهٔ runtime یا اعتبارنامه. ثبت‌نام با سقف بدنهٔ ۶۴ KiB و محدودیت نرخ محافظت می‌شود؛ claim به اثبات هویت، تأیید مدیر، زمان انقضا و مصرف یک‌باره وابسته است. Agent فقط با credential خودش heartbeat/inventory/result می‌دهد؛ مالکیت task پیش از ذخیره بررسی می‌شود.

| روش | مسیر | عملیات | احراز هویت | هویت مجاز | حداقل سطح عملیات | دسترسی | حساسیت |
|---|---|---|---|---|---|---|---|
| GET | `/` | root_redirect | بدون توکن مدیر | همه | Public | بدون دادهٔ خصوصی | کم |
| GET | `/api/admin/v1/agents` | فهرست عوامل ثبت‌شده | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/admin/v1/agents/{agent_id}` | جزئیات یک عامل و آخرین inventory | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/agents/{agent_id}/console/sessions` | باز کردن نشست ترمینال پایتون روی یک عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| POST | `/api/admin/v1/agents/{agent_id}/revoke` | ابطال اعتبارنامه‌ی یک عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| POST | `/api/admin/v1/agents/{agent_id}/screenshot` | درخواست یک‌باره‌ی تصویر صفحه‌ی عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| GET | `/api/admin/v1/agents/{agent_id}/screenshot/{task_id}` | دریافت تصویر PNG ثبت‌شده در نتیجه‌ی تسک | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| POST | `/api/admin/v1/agents/{agent_id}/scripts` | ارسال اسکریپت پایتون مدیریتی برای اجرا روی عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| GET | `/api/admin/v1/agents/{agent_id}/traffic` | نمودار و جریان‌های ترافیک یک عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-actions` | فهرست پیشنهادهای شِیء-را انجام بده (Observe-Only) | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/ai-actions/{action_id}/approve` | تأیید و اجرای یک پیشنهاد بررسی | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + ابزار/مدل محدودشده | بالا |
| POST | `/api/admin/v1/ai-actions/{action_id}/reject` | رد یک پیشنهاد | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-activity` | فهرست رکوردهای فعالیت مدل | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-activity/summary` | وضعیت تجمیعی فعالیت مدل محلی | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-activity/{request_id}` | جزئیات و خط زمانی یک درخواست | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-analyses` | فهرست تحلیل‌های هوش مصنوعی هشدارهای امنیتی | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/ai-analyses/{alert_id}/analyze` | تحلیل فقط یک هشدار با جلوگیری از تکرار | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-analyses/{alert_id}/history` | تاریخچهٔ محفوظ تلاش‌های تحلیل | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/ai-analyses/{alert_id}/reanalyze` | درخواست تحلیل مجدد یک هشدار | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-memories` | فهرست حافظه‌ها (دانش تأییدشده و پیش‌نویس‌ها) | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/ai-memories` | ثبت مستقیم حافظه توسط مدیر (بلافاصله APPROVED) | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| POST | `/api/admin/v1/ai-memories/{memory_id}/approve` | تأیید یک حافظه‌ی پیش‌نهادی | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| POST | `/api/admin/v1/ai-memories/{memory_id}/revoke` | لغو حافظه | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| POST | `/api/admin/v1/ai-memories/{memory_id}/update` | اصلاح حافظه | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/ai-questions` | فهرست سؤال‌های مدیر و پاسخ‌ها | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/ai-questions` | پرسیدن یک سؤال از مدل (همگام، بدون اجرای ابزار) | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + ابزار/مدل محدودشده | بالا |
| GET | `/api/admin/v1/ai-questions/{question_id}` | جزئیات یک سؤال | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/admin/v1/audit` | تاریخچه‌ی حسابرسی عملیات مدیریتی | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/console/sessions` | فهرست نشست‌های ترمینال | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| GET | `/api/admin/v1/console/sessions/{session_id}` | وضعیت نشست و دستورهای آن | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| POST | `/api/admin/v1/console/sessions/{session_id}/commands` | اجرای دستور پایتون در نشست | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| POST | `/api/admin/v1/console/sessions/{session_id}/commands/{command_id}/cancel` | لغو دستور در حال اجرا | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| POST | `/api/admin/v1/console/sessions/{session_id}/terminate` | خاتمه‌ی صریح نشست ترمینال | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| GET | `/api/admin/v1/enrollment-requests` | فهرست درخواست‌های ثبت‌نام خودکار | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/enrollment-requests/{request_id}/approve` | تأیید درخواست ثبت‌نام عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| POST | `/api/admin/v1/enrollment-requests/{request_id}/reject` | رد درخواست ثبت‌نام عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/enrollment-tokens` | فهرست توکن‌های ثبت‌نام اخیر | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/enrollment-tokens` | صدور توکن ثبت‌نام یک‌بارمصرف برای عامل جدید | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/networks` | فهرست شبکه‌های کشف‌شده و محدوده‌ی مؤثر اسکن | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/admin/v1/security-ai` | وضعیت واقعی صف و کنترل تحلیل امنیت | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| PUT | `/api/admin/v1/security-ai/automatic` | تغییر ماندگار تحلیل خودکار؛ پیش‌فرض خاموش | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/admin/v1/tasks` | فهرست تسک‌ها با فیلتر | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/tasks` | ایجاد تسک تشخیصی برای یک عامل | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده + صف تسک عامل | بالا |
| GET | `/api/admin/v1/tasks/{task_id}` | جزئیات و نتیجه‌ی یک تسک | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/admin/v1/tasks/{task_id}/cancel` | لغو تسک در انتظار | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| POST | `/api/agent/v1/enroll` | ثبت‌نام عامل نقطه‌پایان و دریافت اعتبارنامه | بدون توکن مدیر | دارندهٔ توکن ثبت‌نام یا اثبات هویت درخواست | Enrollment | پایگاه داده | بالا |
| POST | `/api/agent/v1/heartbeat` | ارسال ضربان (heartbeat) عامل | Bearer، رد در Backend | فقط عامل احرازهویت‌شده و منابع خودش | Agent | پایگاه داده | بالا |
| POST | `/api/agent/v1/inventory` | ارسال فهرست‌برداری کامل نقطه‌پایان | Bearer، رد در Backend | فقط عامل احرازهویت‌شده و منابع خودش | Agent | پایگاه داده | بالا |
| POST | `/api/agent/v1/register` | معرفی خودکار عامل بدون توکن (در انتظار تأیید مدیر) | بدون توکن مدیر | دارندهٔ توکن ثبت‌نام یا اثبات هویت درخواست | Enrollment | پایگاه داده | بالا |
| POST | `/api/agent/v1/register/{request_id}/claim` | پیگیری وضعیت ثبت‌نام و دریافت اعتبارنامه پس از تأیید | بدون توکن مدیر | دارندهٔ توکن ثبت‌نام یا اثبات هویت درخواست | Enrollment | پایگاه داده | بالا |
| GET | `/api/agent/v1/signing-key` | دریافت کلید امضای مستقل همین عامل | Bearer، رد در Backend | فقط عامل احرازهویت‌شده و منابع خودش | Agent | پایگاه داده | بالا |
| POST | `/api/agent/v1/status` | گزارش وضعیت زمان اجرای عامل | Bearer، رد در Backend | فقط عامل احرازهویت‌شده و منابع خودش | Agent | پایگاه داده | بالا |
| GET | `/api/agent/v1/tasks/next` | دریافت تسک بعدی برای اجرا | Bearer، رد در Backend | فقط عامل احرازهویت‌شده و منابع خودش | Agent | پایگاه داده + صف تسک عامل | بالا |
| POST | `/api/agent/v1/tasks/{task_id}/result` | ارسال نتیجه‌ی اجرای تسک | Bearer، رد در Backend | فقط عامل احرازهویت‌شده و منابع خودش | Agent | پایگاه داده + صف تسک عامل | بالا |
| POST | `/api/agent/v1/traffic` | گزارش دوره‌ای متادیتای ترافیک همان سیستم | Bearer، رد در Backend | فقط عامل احرازهویت‌شده و منابع خودش | Agent | پایگاه داده | بالا |
| GET | `/api/alerts` | دریافت هشدارهای امنیتی با فیلتر | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/dashboard/v1/healthz` | بررسی در دسترس‌بودن مسیر داشبورد (همراه با توکن) | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/dashboard/v1/overview` | آمار کلی سامانه برای صفحه‌ی نمای کلی داشبورد | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/dashboard/v1/settings` | نمای فقط‌خواندنی تنظیمات غیر‌فاش (برای صفحه‌ی تنظیمات داشبورد) | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| GET | `/api/docs` | rtl_docs | بدون توکن مدیر | همه | Public | بدون دادهٔ خصوصی | کم |
| GET | `/api/events` | دریافت رویدادهای Suricata با فیلتر | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/hosts` | دریافت فهرست میزبان‌های شناسایی‌شده | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/hosts/discover` | کشف میزبان در یک محدوده‌ی مجاز | Bearer، رد در Backend | فقط توکن مدیر | Admin Diagnostic | پایگاه داده + ابزار/مدل محدودشده | بالا |
| GET | `/api/hosts/{ip}/fingerprint` | دریافت آخرین شناسایی (fingerprint) میزبان | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/hosts/{ip}/timeline` | دریافت خط زمانی یکپارچه‌ی یک میزبان | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/api/investigations` | دریافت فهرست بررسی‌های انجام‌شده | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/investigations` | اجرای بررسی هوشمند همگام | Bearer، رد در Backend | فقط توکن مدیر | Admin Diagnostic | پایگاه داده + ابزار/مدل محدودشده | بالا |
| GET | `/api/investigations/{inv_id}` | دریافت جزئیات کامل یک بررسی | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/jobs/investigation` | شروع بررسی هوشمند به‌صورت کار پس‌زمینه | Bearer، رد در Backend | فقط توکن مدیر | Admin Diagnostic | پایگاه داده + ابزار/مدل محدودشده | بالا |
| GET | `/api/jobs/{job_id}` | دریافت وضعیت و نتیجه‌ی یک کار پس‌زمینه | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/jobs/{job_id}/cancel` | لغو کار پس‌زمینه | Bearer، رد در Backend | فقط توکن مدیر | Admin Full | پایگاه داده | بالا |
| POST | `/api/scans` | کشف میزبان (نقطه‌پایان سازگاری قبلی) | Bearer، رد در Backend | فقط توکن مدیر | Admin Diagnostic | پایگاه داده + ابزار/مدل محدودشده | بالا |
| GET | `/api/tools` | دریافت فهرست ابزارهای تشخیصی و محدوده‌ی مجاز | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| POST | `/api/tools/{tool_name}` | فراخوانی مستقیم یک ابزار تشخیصی | Bearer، رد در Backend | فقط توکن مدیر | Admin Diagnostic | پایگاه داده + ابزار/مدل محدودشده | بالا |
| GET | `/docs` | docs_redirect | بدون توکن مدیر | همه | Public | بدون دادهٔ خصوصی | کم |
| GET | `/health` | دریافت وضعیت سلامت برنامه | Bearer، رد در Backend | فقط توکن مدیر | Admin Read Only | پایگاه داده | بالا |
| GET | `/healthz` | بررسی عمومی زنده بودن برنامه | بدون توکن مدیر | همه | Public | بدون دادهٔ خصوصی | کم |
| GET/HEAD | `/openapi.json` | تعریف قرارداد FastAPI | عمومی | همه | Public | بدون دادهٔ runtime | کم |
| GET/HEAD | `/dashboard/*` | پوسته و فایل‌های SPA | عمومی؛ داده از API محافظت‌شده | همه برای پوسته | Public | فایل‌های build | کم |
